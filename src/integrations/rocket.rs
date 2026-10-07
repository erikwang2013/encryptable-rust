// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! rocket 0.5 集成。
//!
//! 用 `manage` 注册，处理器把它写在参数里：
//!
//! ```no_run
//! # mod demo {
//! use rocket::{get, routes, Build, Rocket};
//! use encryptable::guard::Guard;
//!
//! #[get("/")]
//! fn store_phone(guard: Guard) -> String {
//!     guard.encrypt("13800138000").unwrap_or_default()
//! }
//!
//! # fn main() {
//! let guard = encryptable::Guard::new(
//!     &encryptable::ArrayConfig::new("0123456789abcdef0123456789abcdef"),
//! )
//! .unwrap();
//! let rocket: Rocket<Build> = rocket::build().manage(guard).mount("/", routes![store_phone]);
//! # let _ = rocket;
//! # }
//! # }
//! ```
//!
//! rocket 的请求守卫走 `Outcome`，且 trait 是 `#[rocket::async_trait]` 的
//! （rocket 自己 re-export 了那个宏，所以不必额外依赖 `async-trait`）。
//!
//! # 托管状态里放的是 [`Guard`] 本身
//!
//! [`Guard`] 内部已经是 `Arc`，克隆一次只是引用计数递增，所以这里是
//! `manage(guard)` 而不是 `manage(Arc::new(guard))` —— rocket 的守卫拿到的是
//! 借用，本来也不需要外面再套一层共享。

use rocket::State;
use rocket::http::Status;
// 注意是 `request::Outcome`（两参数别名 = `outcome::Outcome<S, (Status, E), Status>`），
// 不是 `outcome::Outcome`（三参数）。守卫的返回值用的就是这个别名。
use rocket::request::{FromRequest, Outcome, Request};

use super::GuardNotConfigured;
use crate::guard::Guard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Guard {
    type Error = GuardNotConfigured;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.guard::<&State<Guard>>().await {
            Outcome::Success(state) => Outcome::Success(state.inner().clone()),
            // 忘了 manage(...)：装配错误 → 500，不 Forward（没有别的路由能处理它）。
            // 别名的 Error 分支装的是 `(Status, E)` 而不是裸的 E。
            Outcome::Error(_) | Outcome::Forward(_) => {
                Outcome::Error((Status::InternalServerError, GuardNotConfigured))
            }
        }
    }
}

/// 现成的项目图标路由。
///
/// ```no_run
/// # #[cfg(feature = "rocket")]
/// # {
/// use rocket::routes;
/// use encryptable::integrations::rocket::pet;
///
/// let rocket = rocket::build().mount("/", routes![pet]);
/// # }
/// ```
#[rocket::get("/pet.svg")]
pub fn pet() -> (rocket::http::ContentType, &'static str) {
    (rocket::http::ContentType::SVG, crate::pet::svg())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use rocket::local::blocking::Client;
    use rocket::{get, routes};

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    /// 密文是**标准 base64**，字母表里有 `/` —— 直接放进 URL 路径会被当成
    /// 路径分隔符，请求落到别的路由上变成 404。而 `/` 出不出现取决于随机
    /// nonce，于是表现为「有时候 404」。
    ///
    /// 要把密文塞进 URL 就得换 base64url 字母表（`+`→`-`，`/`→`_`）。
    /// 这条不是本库的限制，是 URL 的：任何标准 base64 进路径都要这么处理。
    fn to_url_safe(b64: &str) -> String {
        b64.replace('+', "-").replace('/', "_")
    }

    fn from_url_safe(s: &str) -> String {
        s.replace('-', "+").replace('_', "/")
    }

    #[get("/encrypt")]
    fn encrypt_route(guard: Guard) -> String {
        to_url_safe(&guard.encrypt("13800138000").unwrap())
    }

    #[get("/decrypt/<payload>")]
    fn decrypt_route(guard: Guard, payload: &str) -> String {
        guard
            .decrypt_text(&from_url_safe(payload))
            .unwrap_or_else(|_| "解不开".into())
    }

    #[test]
    fn guard_is_injectable_end_to_end() {
        let rocket = rocket::build()
            .manage(guard())
            .mount("/", routes![encrypt_route, decrypt_route]);
        let client = Client::tracked(rocket).expect("rocket 应当能启动");

        let res = client.get("/encrypt").dispatch();
        assert_eq!(res.status(), Status::Ok);
        let cipher = res.into_string().unwrap();
        assert!(cipher.len() > 20, "应当拿到一段密文，实际 {cipher:?}");
        assert!(!cipher.contains('/'), "URL 安全化之后不该再有斜杠");

        // 拿刚加密出来的密文再解回去 —— 证明两个请求用的是同一把密钥
        let res = client.get(format!("/decrypt/{cipher}")).dispatch();
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.into_string().unwrap(), "13800138000");
    }

    /// 反复跑，确保没有「取决于 nonce」的偶发失败。
    ///
    /// 之前这里就是间歇性 404：密文里只要出现一个 `/`，路由就匹配不上。
    /// 一条测试跑一次只能覆盖 1/2 的概率，所以要跑够次数。
    #[test]
    fn url_safe_round_trip_holds_for_many_nonces() {
        let g = guard();
        for _ in 0..64 {
            let cipher = g.encrypt("13800138000").unwrap();
            let safe = to_url_safe(&cipher);

            assert!(!safe.contains('/'), "仍有斜杠：{safe}");
            assert!(!safe.contains('+'), "仍有加号：{safe}");
            assert_eq!(from_url_safe(&safe), cipher, "URL 安全化不可逆");
            assert_eq!(
                g.decrypt_text(&from_url_safe(&safe)).unwrap(),
                "13800138000"
            );
        }
    }

    /// 忘了 `manage(...)` 时是 500，不是 panic。
    #[test]
    fn missing_managed_state_is_a_500() {
        let rocket = rocket::build().mount("/", routes![encrypt_route]);
        let client = Client::tracked(rocket).expect("rocket 应当能启动");

        let res = client.get("/encrypt").dispatch();
        assert_eq!(res.status(), Status::InternalServerError);
    }

    #[test]
    fn pet_route_serves_the_artwork() {
        let rocket = rocket::build().mount("/", routes![pet]);
        let client = Client::tracked(rocket).expect("rocket 应当能启动");

        let res = client.get("/pet.svg").dispatch();
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(
            res.content_type().map(|c| c.to_string()),
            Some("image/svg+xml".to_owned()),
            "缺了 Content-Type，浏览器会把 SVG 当纯文本渲染"
        );
        assert_eq!(res.into_string().unwrap(), crate::pet::svg());
    }
}
