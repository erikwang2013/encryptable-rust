// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! salvo 1.0 集成。
//!
//! 用 `affix_state` 把守卫放进 `Depot`，处理器用 [`Extractible`] 取出来：
//!
//! ```no_run
//! # mod demo {
//! use encryptable::guard::Guard;
//! use salvo::prelude::*;
//!
//! #[handler]
//! async fn store_phone(guard: Guard) -> String {
//!     guard.encrypt("13800138000").unwrap_or_default()
//! }
//!
//! # fn main() {
//! let guard = encryptable::Guard::new(
//!     &encryptable::ArrayConfig::new("0123456789abcdef0123456789abcdef"),
//! )
//! .unwrap();
//!
//! // 把守卫放进 Depot。生产里通常用 salvo_extra 的
//! // `affix_state::inject(guard)`（需要开 salvo 的 `affix-state` feature）；
//! // 这里直接放，好让这段示例只依赖 salvo 核心。
//! let mut depot = Depot::new();
//! depot.insert_typed(guard);
//!
//! let router = Router::new().get(store_phone);
//! # let _ = (router, depot);
//! # }
//! # }
//! ```
//!
//! # 注意 salvo 1.0 的破坏性变更
//!
//! salvo 1.0（2026-09-24 发布）把状态中间件挪到了
//! `salvo_extra::affix_state`，且改为返回 `AffixList` 的自由函数
//! （`affix_state::inject(v)`）。网上大量写于 0.7x/0.96 的 `Depot::inject`、
//! `Router::aim` 用法的资料对 1.x **不适用**。

use salvo::extract::Metadata;
use salvo::http::StatusCode;
use salvo::prelude::{Depot, Request, Response, Text};
use salvo::writing::Writer;
use salvo::{Extractible, async_trait};

use super::GuardNotConfigured;
use crate::guard::Guard;

/// 让「忘了 inject」这件事在 salvo 里表现为一条 500 响应。
#[async_trait]
impl Writer for GuardNotConfigured {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.render(Text::Plain(self.to_string()));
    }
}

impl<'ex> Extractible<'ex> for Guard {
    fn metadata() -> &'static Metadata {
        // salvo 的 `Metadata::new` 是 const fn，直接放进 static
        static METADATA: Metadata = Metadata::new("Guard");
        &METADATA
    }

    // trait 里的错误类型写的是 `impl Writer + Send + Debug + 'static`，这里收窄成
    // 具体的 `GuardNotConfigured`。这是刻意的：调用方因此能 `match` 到具体类型，
    // 而不是面对一个匿名的 impl trait。
    #[allow(refining_impl_trait_reachable)]
    async fn extract(
        _req: &'ex mut Request,
        depot: &'ex mut Depot,
    ) -> Result<Self, GuardNotConfigured> {
        depot
            .get_typed::<Guard>()
            .cloned()
            .map_err(|_| GuardNotConfigured)
    }
}

/// 把项目形象写进响应，带上正确的 `Content-Type`。
///
/// 单独拆出来是因为它不依赖 salvo 的处理器机制，任何拿得到 `&mut Response`
/// 的地方都能用；[`pet`] 只是它的一层 `#[handler]` 包装。
pub fn write_pet(res: &mut Response) {
    res.headers_mut().insert(
        salvo::http::header::CONTENT_TYPE,
        salvo::http::HeaderValue::from_static(crate::pet::CONTENT_TYPE),
    );
    let _ = res.write_body(crate::pet::svg());
}

/// 现成的项目图标处理器。
///
/// ```no_run
/// # #[cfg(feature = "salvo")]
/// # {
/// use salvo::prelude::*;
/// use encryptable::integrations::salvo::pet;
///
/// let router = Router::new().get(pet);
/// # }
/// ```
#[salvo::handler]
pub async fn pet(res: &mut Response) {
    write_pet(res);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    #[test]
    fn extracts_from_depot() {
        let mut depot = Depot::new();
        depot.insert_typed(guard());

        let mut req = Request::new();
        let extracted = futures_lite_block_on(Guard::extract(&mut req, &mut depot)).unwrap();
        assert_eq!(extracted.ring_len(), 1);
    }

    /// 忘了 inject 时是装配错误，翻译成 500。
    #[test]
    fn missing_depot_entry_is_an_error() {
        let mut depot = Depot::new();
        let mut req = Request::new();
        let err = futures_lite_block_on(Guard::extract(&mut req, &mut depot)).unwrap_err();
        assert_eq!(err, GuardNotConfigured);
    }

    #[test]
    fn handler_and_state_share_one_encrypter() {
        let state = guard();
        let token = state.encrypt("共享").unwrap();

        let mut depot = Depot::new();
        depot.insert_typed(state);

        let mut req = Request::new();
        let extracted = futures_lite_block_on(Guard::extract(&mut req, &mut depot)).unwrap();
        assert_eq!(extracted.decrypt_text(&token).unwrap(), "共享");
    }

    /// 图标端点：带对 MIME 类型，且写进去的字节数正好是形象的长度。
    ///
    /// 这里读 `ResBody::size()` 而不是把 body 抽干：salvo 的 `ResBody` 没有
    /// 现成的取字符串方法，要读它得手动 poll `http_body::Body` 的帧，
    /// 为一个测试引入那一套不划算。长度对上已经能挡住「写错内容 / 写空」。
    #[test]
    fn write_pet_serves_the_artwork() {
        let mut res = Response::new();
        write_pet(&mut res);

        assert_eq!(
            res.headers()
                .get(salvo::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/svg+xml"),
            "缺了 Content-Type，浏览器会把 SVG 当纯文本渲染"
        );

        let body = res.take_body();
        assert_eq!(
            body.size(),
            Some(crate::pet::SVG_LEN as u64),
            "写进响应的字节数与形象长度不符"
        );
        assert!(!body.is_none(), "响应体是空的");
    }

    /// salvo 的 `Extractible::extract` 是异步的，但测试里没必要引入完整运行时 ——
    /// 这些 future 不含真正的 I/O，手动 poll 一次即可完成。
    fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Waker};

        let mut fut = std::pin::pin!(fut);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(out) => return out,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
