// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! actix-web 4 集成。
//!
//! 守卫注册进 `app_data`，处理器把它直接写在参数里：
//!
//! ```no_run
//! # mod demo {
//! use actix_web::{web, App, HttpServer};
//! use encryptable::guard::Guard;
//!
//! async fn store_phone(guard: Guard) -> String {
//!     guard.encrypt("13800138000").unwrap_or_default()
//! }
//!
//! # fn main() {
//! let guard = /* … */;
//! let app = move || {
//!     App::new()
//!         .app_data(web::Data::new(guard.clone()))
//!         .route("/", web::get().to(store_phone))
//! };
//! # let _ = app;
//! # }
//! # }
//! ```
//!
//! # 与 [`Guarded`](super::Guarded) 的关系
//!
//! actix 没有「单一应用状态」这个概念，它的 `app_data` 是按**类型**取值的，
//! 所以这里走的是 `Data<Guard>` 这条路，而不是 [`Guarded`](super::Guarded)。
//!
//! 状态结构体比较大时，注册 `Data<AppState>` 并让 `AppState` 实现
//! [`Guarded`](super::Guarded)，然后在处理器里写 `state.guard()` —— 那条路
//! 一样通，只是取用方式不同。

use std::future::{Ready, ready};

use actix_web::dev::Payload;
use actix_web::web::Data;
use actix_web::{Error, FromRequest, HttpRequest};

use super::GuardNotConfigured;
use crate::guard::Guard;

impl FromRequest for Guard {
    type Error = Error;
    /// 纯同步取值，不需要装箱 —— 拷贝一次 `Arc` 而已。
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.app_data::<Data<Guard>>() {
            Some(data) => {
                // `Data<T>` 的 `Deref::Target` 是 `Arc<T>`（不是 `T`），所以这里
                // 靠连续两次解引用拿到 `&Guard`，而不是 `(**data).clone()`
                // —— 那会得到一个 `Arc<Guard>`。
                let guard: &Guard = data;
                ready(Ok(guard.clone()))
            }
            // 忘了 app_data(...) —— 装配错误，500 而不是 4xx
            None => ready(Err(actix_web::error::ErrorInternalServerError(
                GuardNotConfigured,
            ))),
        }
    }
}

/// 现成的项目图标处理器。
///
/// ```no_run
/// # #[cfg(feature = "actix-web")]
/// # {
/// use actix_web::{App, web};
/// use encryptable::integrations::actix::pet;
///
/// let app = App::new().route("/pet.svg", web::get().to(pet));
/// # }
/// ```
pub async fn pet() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok()
        .content_type(crate::pet::CONTENT_TYPE)
        .body(crate::pet::svg())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use actix_web::test;

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    #[actix_web::test]
    async fn extracts_from_app_data() {
        let req = test::TestRequest::default()
            .app_data(Data::new(guard()))
            .to_http_request();

        let extracted = Guard::from_request(&req, &mut Payload::None).await.unwrap();
        assert_eq!(extracted.ring_len(), 1);
    }

    /// 忘了注册时给出明确的 500，而不是 panic 或 400。
    #[actix_web::test]
    async fn missing_app_data_is_a_500() {
        let req = test::TestRequest::default().to_http_request();
        let err = Guard::from_request(&req, &mut Payload::None)
            .await
            .unwrap_err();
        assert_eq!(
            err.as_response_error().status_code(),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// 处理器拿到的与注册进去的是同一把密钥 —— 密文互通。
    #[actix_web::test]
    async fn handler_and_state_share_one_encrypter() {
        let state = guard();
        let token = state.encrypt("共享").unwrap();

        let req = test::TestRequest::default()
            .app_data(Data::new(state))
            .to_http_request();
        let extracted = Guard::from_request(&req, &mut Payload::None).await.unwrap();

        assert_eq!(extracted.decrypt_text(&token).unwrap(), "共享");
    }

    /// `Data::from(arc)` 复用同一个分配，不嵌套第二层 Arc。
    #[actix_web::test]
    async fn data_from_arc_shares_the_allocation() {
        use std::sync::Arc;

        let shared = Arc::new(guard());
        let token = shared.encrypt("x").unwrap();

        let req = test::TestRequest::default()
            .app_data(Data::from(shared.clone()))
            .to_http_request();
        let extracted = Guard::from_request(&req, &mut Payload::None).await.unwrap();

        assert_eq!(extracted.decrypt_text(&token).unwrap(), "x");
        // 原 Arc 与 Data 里的仍是同一份
        assert_eq!(Arc::strong_count(&shared), 2);
    }

    #[actix_web::test]
    async fn pet_handler_serves_the_artwork() {
        let app = actix_web::test::init_service(
            actix_web::App::new().route("/pet.svg", actix_web::web::get().to(pet)),
        )
        .await;

        let req = test::TestRequest::get().uri("/pet.svg").to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_eq!(
            res.headers()
                .get(actix_web::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/svg+xml")
        );

        let body = test::read_body(res).await;
        assert_eq!(std::str::from_utf8(&body).unwrap(), crate::pet::svg());
    }
}
