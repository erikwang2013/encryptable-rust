// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! axum 0.8 集成。
//!
//! 实现 [`FromRequestParts`]，于是处理器可以直接把 [`Guard`] 写在参数里：
//!
//! ```no_run
//! use axum::{routing::get, Router};
//! use encryptable::guard::Guard;
//! use encryptable::integrations::Guarded;
//!
//! #[derive(Clone)]
//! struct AppState { encryption: Guard }
//! impl Guarded for AppState {
//!     fn guard(&self) -> &Guard { &self.encryption }
//! }
//!
//! async fn store_phone(guard: Guard) -> String {
//!     guard.encrypt("13800138000").unwrap_or_default()
//! }
//!
//! let state = AppState { encryption: /* 你的守卫 */ todo!() };
//! let app: Router = Router::new().route("/", get(store_phone)).with_state(state);
//! # let _ = app;
//! ```
//!
//! # 提取是不会失败的
//!
//! `Guarded::guard()` 返回引用，取不到守卫只可能是状态装配错了 —— 那是编译期
//! 就该发现的事，不是运行期。所以 `Rejection` 是 [`Infallible`]：这个提取器
//! 永远不会把请求拒掉。
//!
//! 加解密本身的失败（密钥不对、密文被改）发生在处理器体里，由调用方决定怎么
//! 回应 —— 本库不替应用决定「解密失败该返回 500 还是 422」。

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use super::Guarded;
use crate::guard::Guard;

/// 提取器实现的宿主类型。写出来只是为了让「守卫是怎么进来的」这件事
/// 在文档与再导出里有个名字。
pub type GuardExtractor = Guard;

impl<S> FromRequestParts<S> for Guard
where
    S: Guarded + Send + Sync,
{
    type Rejection = Infallible;

    /// 从应用状态取守卫，克隆一份交给处理器。
    ///
    /// 克隆的是 `Arc`，不是密钥材料 —— 每请求的成本就是一次引用计数递增。
    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(state.guard().clone())
    }
}

/// 现成的项目图标处理器：挂到任意路径上即可对外提供项目宠物。
///
/// ```no_run
/// # #[cfg(feature = "axum")]
/// # {
/// use axum::{Router, routing::get};
/// use encryptable::integrations::axum::pet;
///
/// let app: Router = Router::new().route("/pet.svg", get(pet));
/// # }
/// ```
///
/// 带上 `Content-Type: image/svg+xml` —— 少了这个头，浏览器会把 SVG 当纯文本，
/// 用户看到的是一屏 XML 而不是那只挂钥匙环的锁。
///
/// bee-rust 与 e-cat 都建在 axum 之上，这个处理器同样能挂到它们上面。
pub async fn pet() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, crate::pet::CONTENT_TYPE)],
        crate::pet::svg(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt as _;

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    /// 状态就是一把守卫时，零样板可用。
    #[derive(Clone)]
    struct BareState {
        encryption: Guard,
    }
    impl Guarded for BareState {
        fn guard(&self) -> &Guard {
            &self.encryption
        }
    }

    /// 真实形状：守卫只是状态里的一个字段，旁边还有别的东西。
    #[derive(Clone)]
    struct AppState {
        #[allow(dead_code)]
        pool: std::sync::Arc<String>,
        encryption: Guard,
    }
    impl Guarded for AppState {
        fn guard(&self) -> &Guard {
            &self.encryption
        }
    }

    /// 直接调 trait 方法，不起服务器 —— 确认签名接得上。
    #[tokio::test]
    async fn extracts_directly_from_parts() {
        let state = AppState {
            pool: std::sync::Arc::new("pool".into()),
            encryption: guard(),
        };
        let (mut parts, _) = Request::new(()).into_parts();

        let extracted = Guard::from_request_parts(&mut parts, &state).await.unwrap();
        assert_eq!(extracted.ring_len(), 1);
    }

    /// 端到端：处理器参数里直接写 `Guard`。
    #[tokio::test]
    async fn handler_can_take_a_guard_argument() {
        async fn handler(guard: Guard) -> String {
            let cipher = guard.encrypt("13800138000").unwrap();
            guard.decrypt_text(&cipher).unwrap()
        }

        let state = AppState {
            pool: std::sync::Arc::new("pool".into()),
            encryption: guard(),
        };
        let app = Router::new().route("/", get(handler)).with_state(state);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"13800138000");
    }

    /// 处理器拿到的守卫与状态里的是同一把 —— 密文互通。
    ///
    /// 状态先用**它自己**的守卫加密一段数据放进扩展里，处理器用提取出来的守卫
    /// 解开。解不开就说明两者不是同一把密钥。
    #[tokio::test]
    async fn handler_and_state_share_one_encrypter() {
        async fn handler(guard: Guard, Extension(token): Extension<String>) -> String {
            guard
                .decrypt_text(&token)
                .unwrap_or_else(|_| "解不开".into())
        }

        let state = BareState {
            encryption: guard(),
        };
        let token = state.encryption.encrypt("共享").unwrap();

        let app = Router::new()
            .route("/", get(handler))
            .layer(Extension(token))
            .with_state(state);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], "共享".as_bytes());
    }

    /// 宠物端点真的能挂到路由上，并且带着正确的 MIME 类型。
    #[tokio::test]
    async fn pet_handler_serves_the_artwork() {
        let app: Router = Router::new().route("/pet.svg", get(pet));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/pet.svg")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/svg+xml"),
            "缺了 Content-Type，浏览器会把 SVG 当纯文本渲染"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.starts_with("<svg"), "返回的不是 SVG");
        assert_eq!(text, crate::pet::svg(), "端点给的不是那一份形象");
    }
}
