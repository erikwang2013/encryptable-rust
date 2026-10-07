// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! e-cat 集成。
//!
//! e-cat 的 HTTP 传输层是 axum，中间件层是 **tower 的 `Layer`/`Service`**，
//! 用 `tower::ServiceBuilder` 组装。它没有自己的「中间件 trait」，所以这里
//! 就是一个标准的 tower 层：把 [`Guard`] 塞进请求扩展，处理器用
//! `Extension<Guard>` 取出来。
//!
//! ```no_run
//! # mod demo {
//! use encryptable::guard::Guard;
//! use encryptable::integrations::ecat::GuardLayer;
//! use tower::ServiceBuilder;
//!
//! # fn main() {
//! let guard = encryptable::Guard::new(
//!     &encryptable::ArrayConfig::new("0123456789abcdef0123456789abcdef"),
//! )
//! .unwrap();
//! let middleware = ServiceBuilder::new().layer(GuardLayer::new(guard));
//! # let _ = middleware;
//! # }
//! # }
//! ```
//!
//! # 为什么这不只是「给 e-cat 用的」
//!
//! 它是一个不依赖 e-cat 的普通 tower 层 —— e-cat 只是把它接进来的那个框架。
//! 与 e-cat 自身的 `ecat-middleware::ValidateLayer` 是同一个形状，可以并排
//! 放进同一个 `ServiceBuilder`。
//!
//! # 为什么不必装箱
//!
//! 这一层不改写响应、不改写错误，只是往请求里塞一个 `Extension`，所以
//! `type Future = S::Future` —— 直接透传内层的 future，没有 `Pin<Box<dyn ...>>`，
//! 也没有 `futures` 依赖。

use std::task::{Context, Poll};

use http::Request;
use tower::{Layer, Service};

use crate::guard::Guard;

/// 把 [`Guard`] 注入每个请求扩展的 tower 层。
#[derive(Clone, Debug)]
pub struct GuardLayer {
    guard: Guard,
}

impl GuardLayer {
    /// 用一把共享守卫构造。
    pub fn new(guard: Guard) -> Self {
        Self { guard }
    }
}

impl<S> Layer<S> for GuardLayer {
    type Service = GuardService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GuardService {
            inner,
            guard: self.guard.clone(),
        }
    }
}

/// [`GuardLayer`] 产出的服务。
#[derive(Clone, Debug)]
pub struct GuardService<S> {
    inner: S,
    guard: Guard,
}

impl<S, B> Service<Request<B>> for GuardService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    /// 透传内层的 future —— 本层不做任何异步改写。
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // 处理器侧用 `Extension<Guard>` 或直接 `Guard`（若也用了 axum 适配层）取用
        req.extensions_mut().insert(self.guard.clone());
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use std::convert::Infallible;
    use tower::service_fn;

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    /// 内层服务：从扩展里把守卫取出来，回报密钥环长度。
    /// 模拟一个真实的处理器 —— 拿不到守卫就直接炸，测试才有意义。
    async fn echo_ring_len(req: Request<()>) -> Result<String, Infallible> {
        let g = req
            .extensions()
            .get::<Guard>()
            .expect("守卫应当已被注入")
            .clone();
        Ok(g.ring_len().to_string())
    }

    #[tokio::test]
    async fn injects_the_guard_into_extensions() {
        let mut svc = GuardLayer::new(guard()).layer(service_fn(echo_ring_len));
        let res = svc.call(Request::new(())).await.unwrap();
        assert_eq!(res, "1");
    }

    /// 注进去的与外面持有的是同一把密钥 —— 密文互通。
    #[tokio::test]
    async fn injected_guard_shares_the_key() {
        let state = guard();
        let token = state.encrypt("共享").unwrap();

        let inner = service_fn(move |req: Request<()>| {
            let token = token.clone();
            async move {
                let g = req.extensions().get::<Guard>().unwrap().clone();
                Ok::<_, Infallible>(g.decrypt_text(&token).unwrap_or_else(|_| "解不开".into()))
            }
        });

        let mut svc = GuardLayer::new(state).layer(inner);
        let res = svc.call(Request::new(())).await.unwrap();
        assert_eq!(res, "共享");
    }

    /// 多个请求走同一个服务，注入照常。
    #[tokio::test]
    async fn works_across_multiple_requests() {
        let mut svc = GuardLayer::new(guard()).layer(service_fn(echo_ring_len));
        for _ in 0..3 {
            assert_eq!(svc.call(Request::new(())).await.unwrap(), "1");
        }
    }

    /// 与 e-cat 自己的中间件并排组装（同一个 ServiceBuilder 里）。
    #[tokio::test]
    async fn composes_with_ecat_service_builder() {
        use tower::ServiceBuilder;

        let mut svc = ServiceBuilder::new()
            .layer(GuardLayer::new(guard()))
            .service(service_fn(echo_ring_len));

        assert_eq!(svc.call(Request::new(())).await.unwrap(), "1");
    }
}
