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
//! let guard = /* … */;
//! let router = Router::new().hoop(affix_state::inject(guard)).get(store_phone);
//! # let _ = router;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use salvo::prelude::*;

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

    /// salvo 的 `Extractible::extract` 是异步的，但测试里没必要引入完整运行时 ——
    /// 这些 future 不含真正的 I/O，手动 poll 一次即可完成。
    fn futures_lite_block_on<F: std::future::Future>(mut fut: F) -> F::Output {
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
