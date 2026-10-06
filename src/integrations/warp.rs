// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! warp 0.4 集成。
//!
//! warp 没有提取器 trait，也没有 `with_state` —— 它靠**闭包捕获**把一个
//! `Clone` 的值接进过滤器链。所以这里没有 `impl`，只有一个组合子：
//!
//! ```no_run
//! # mod demo {
//! use encryptable::guard::Guard;
//! use encryptable::integrations::warp::with_guard;
//! use warp::Filter;
//!
//! let guard = /* … */;
//! let route = warp::path("encrypt")
//!     .and(with_guard(guard))
//!     .map(|guard: Guard| guard.encrypt("13800138000").unwrap_or_default());
//! # let _ = route;
//! # }
//! ```
//!
//! 这与 warp 文档里 `warp::any().map(move || state.clone())` 的写法是同一件事，
//! 只是把「克隆共享状态」这一步收进了一个有名字的组合子，免得每个项目各写一遍。

use std::convert::Infallible;

use warp::Filter;

use crate::guard::Guard;

/// 造一个产出 [`Guard`] 的过滤器，供 `.and(...)` 接进路由链。
///
/// 每次请求克隆一次 `Arc`（引用计数递增），不含任何密钥拷贝。
pub fn with_guard(guard: Guard) -> impl Filter<Extract = (Guard,), Error = Infallible> + Clone {
    warp::any().map(move || guard.clone())
}

/// 现成的项目图标过滤器。
///
/// ```no_run
/// # #[cfg(feature = "warp")]
/// # {
/// use encryptable::integrations::warp::pet;
///
/// let route = pet();
/// # let _ = route;
/// # }
/// ```
pub fn pet() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("pet.svg").map(|| {
        warp::reply::with_header(crate::pet::svg(), "content-type", crate::pet::CONTENT_TYPE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use warp::Filter;

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    #[tokio::test]
    async fn filter_yields_the_guard() {
        let route = warp::any()
            .and(with_guard(guard()))
            .map(|g: Guard| g.ring_len().to_string());

        let value = warp::test::request().filter(&route).await.unwrap();
        assert_eq!(value, "1");
    }

    /// 同一把守卫进到处理器里，密文互通。
    #[tokio::test]
    async fn handler_and_state_share_one_encrypter() {
        let state = guard();
        let token = state.encrypt("共享").unwrap();

        let route = warp::any()
            .and(with_guard(guard()))
            .map(move |g: Guard| g.decrypt_text(&token).unwrap_or_else(|_| "解不开".into()));

        let value = warp::test::request().filter(&route).await.unwrap();
        assert_eq!(value, "共享");
    }

    /// 过滤器必须 `Clone` —— warp 的每个组合子都要求这一点。
    #[tokio::test]
    async fn filter_is_cloneable_and_reusable() {
        let filter = with_guard(guard());
        let a = filter.clone();
        let b = filter;

        let route_a = warp::any().and(a).map(|g: Guard| g.ring_len());
        let route_b = warp::any().and(b).map(|g: Guard| g.ring_len());

        assert_eq!(warp::test::request().filter(&route_a).await.unwrap(), 1);
        assert_eq!(warp::test::request().filter(&route_b).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn pet_filter_serves_the_artwork() {
        let res = warp::test::request().path("/pet.svg").reply(&pet()).await;

        assert_eq!(res.status(), 200);
        assert_eq!(
            res.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("image/svg+xml"),
            "缺了 Content-Type，浏览器会把 SVG 当纯文本渲染"
        );
        assert_eq!(res.body(), crate::pet::svg().as_bytes());
    }

    /// 路径不匹配时应当 404，而不是把形象吐给所有路径。
    #[tokio::test]
    async fn pet_filter_does_not_answer_other_paths() {
        let res = warp::test::request().path("/other").reply(&pet()).await;
        assert_eq!(res.status(), 404);
    }
}
