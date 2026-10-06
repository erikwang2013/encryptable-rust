// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! poem 3 集成。
//!
//! 用 `.data(guard)` 注册，处理器把守卫写在参数里：
//!
//! ```no_run
//! # mod demo {
//! use poem::{Route, get, handler};
//! use encryptable::guard::Guard;
//!
//! #[handler]
//! async fn store_phone(guard: Guard) -> String {
//!     guard.encrypt("13800138000").unwrap_or_default()
//! }
//!
//! # fn main() {
//! let guard = /* … */;
//! let app = Route::new().at("/", get(store_phone)).data(guard);
//! # let _ = app;
//! # }
//! # }
//! ```
//!
//! poem 的 `.data(v)` 要求 `T: Clone + Send + Sync + 'static`；[`Guard`] 满足，
//! 且克隆的只是一次 `Arc` 引用计数递增。

use poem::http::StatusCode;
use poem::web::{FromRequest, RequestBody};
use poem::{Error, Request, Result};

use super::GuardNotConfigured;
use crate::guard::Guard;

impl<'a> FromRequest<'a> for Guard {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        req.extensions().get::<Guard>().cloned().ok_or_else(|| {
            Error::from_string(
                GuardNotConfigured.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })
    }
}

/// 现成的项目图标处理器。
///
/// ```no_run
/// # #[cfg(feature = "poem")]
/// # {
/// use poem::{Route, get};
/// use encryptable::integrations::poem::pet;
///
/// let app = Route::new().at("/pet.svg", get(pet));
/// # }
/// ```
// poem 的处理器要过 `#[handler]` 宏才能实现 `IntoEndpoint` —— 少了它，
// `Route::at(.., get(pet))` 直接编译不过。
#[poem::handler]
pub async fn pet() -> poem::Response {
    poem::Response::builder()
        .content_type(crate::pet::CONTENT_TYPE)
        .body(crate::pet::svg())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use poem::Request;

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    async fn extract(req: &Request) -> Result<Guard> {
        let mut body = RequestBody::default();
        Guard::from_request(req, &mut body).await
    }

    #[tokio::test]
    async fn extracts_from_request_extensions() {
        let mut req = Request::builder().finish();
        req.extensions_mut().insert(guard());

        let extracted = extract(&req).await.unwrap();
        assert_eq!(extracted.ring_len(), 1);
    }

    /// 忘了 `.data(...)` 时是 500，不是 400 —— 这是服务端装配问题。
    #[tokio::test]
    async fn missing_data_is_a_500() {
        let req = Request::builder().finish();
        let err = extract(&req).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn handler_and_state_share_one_encrypter() {
        let state = guard();
        let token = state.encrypt("共享").unwrap();

        let mut req = Request::builder().finish();
        req.extensions_mut().insert(state);

        let extracted = extract(&req).await.unwrap();
        assert_eq!(extracted.decrypt_text(&token).unwrap(), "共享");
    }

    #[tokio::test]
    async fn pet_handler_serves_the_artwork() {
        use poem::Endpoint;

        let app = poem::Route::new().at("/pet.svg", poem::get(pet));
        let req = Request::builder()
            .uri(poem::http::Uri::from_static("/pet.svg"))
            .finish();
        let res = app.get_response(req).await;

        assert_eq!(res.status(), poem::http::StatusCode::OK);
        assert_eq!(
            res.content_type().map(|c| c.to_string()),
            Some("image/svg+xml".to_owned()),
            "缺了 Content-Type，浏览器会把 SVG 当纯文本渲染"
        );
        assert_eq!(
            res.into_body().into_string().await.unwrap(),
            crate::pet::svg()
        );
    }
}
