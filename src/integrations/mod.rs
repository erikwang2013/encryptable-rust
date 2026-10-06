// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 框架集成：把 [`Guard`] 按各框架的惯例交给处理器。
//!
//! 每个框架一个 feature，全部 opt-in，默认构建一个都不拉。
//!
//! ```text
//! features = ["axum"]       ->  Guard 作为 axum 提取器
//! features = ["actix-web"]  ->  Guard 实现 FromRequest
//! features = ["rocket"]     ->  Guard 作为 rocket 请求守卫
//! features = ["poem"]       ->  Guard 实现 FromRequest
//! features = ["salvo"]      ->  Guard 实现 Extractible
//! features = ["warp"]       ->  with_guard 组合子
//! features = ["bee-rust"]   ->  bee-rust 路由吃 axum handler，复用 axum 适配
//! features = ["ecat"]       ->  e-cat 的 tower Layer/Service
//! ```
//!
//! # 一致的心智模型
//!
//! 框架各不相同，但它们在这里要解决的是同一个问题：**处理器怎么拿到那个共享的
//! 加密器**。所有适配层都归结为同一件事 —— 从应用状态里取出 [`Guard`]，克隆一份
//! （`Arc` 递增引用计数，不含密钥拷贝）交给处理器。
//!
//! # 为什么需要一个 [`Guarded`] trait
//!
//! 真实应用的状态结构体不会只有一把加密器，通常还挂着连接池、配置、限流器。
//! 如果直接实现「从状态里取守卫」，那就得为每个状态类型写一遍提取代码。所以这里
//! 定义一个只有一件事的 trait：你的状态告诉本库「守卫在哪个字段」，剩下的提取
//! 逻辑由适配层提供。
//!
//! ```no_run
//! # #[cfg(feature = "axum")]
//! # mod demo {
//! use std::sync::Arc;
//! use encryptable::guard::Guard;
//! use encryptable::integrations::Guarded;
//!
//! #[derive(Clone)]
//! struct AppState {
//!     pool: Arc<()>,          // 你的连接池、配置……
//!     encryption: Guard,      // 加密守卫
//! }
//!
//! impl Guarded for AppState {
//!     fn guard(&self) -> &Guard { &self.encryption }
//! }
//!
//! // 处理器直接声明它要一把守卫，不必再 `State(state)` 再手动取字段
//! async fn create_user(guard: Guard) -> String {
//!     guard.encrypt("13800138000").unwrap_or_default()
//! }
//! # }
//! ```

use crate::guard::Guard;

/// 把 [`Guard`] 从应用状态里取出来。
///
/// 实现它只需要指向一个字段。适配层据此提供各框架的提取器 / 守卫。
///
/// [`Guard`] 自身与 `Arc<Guard>` 已经实现了它，所以「状态就是一把守卫」这种
/// 最小场景不需要写任何代码。
pub trait Guarded: Send + Sync {
    /// 取出守卫。永远成功 —— 取不到说明状态装配错了，那是编译期该发现的事。
    fn guard(&self) -> &Guard;
}

impl Guarded for Guard {
    fn guard(&self) -> &Guard {
        self
    }
}

impl Guarded for std::sync::Arc<Guard> {
    fn guard(&self) -> &Guard {
        self
    }
}

/// 应用没有把守卫注册进框架的状态/数据槽。
///
/// 这是**装配错误**：代码编译得过，但启动时忘了 `manage(guard)` / `app_data(...)`。
/// 各框架把它翻译成自己的拒绝类型，最终都是一条 500 —— 用户没做错任何事，
/// 服务端配置漏了一步，所以不该是 4xx。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardNotConfigured;

impl std::fmt::Display for GuardNotConfigured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "应用状态里没有注册加密守卫（Encryptable Guard）—— \
             请检查框架的 manage / app_data / with_state / data 装配步骤",
        )
    }
}

impl std::error::Error for GuardNotConfigured {}

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix-web")]
pub mod actix;

#[cfg(feature = "rocket")]
pub mod rocket;

#[cfg(feature = "poem")]
pub mod poem;

#[cfg(feature = "salvo")]
pub mod salvo;

#[cfg(feature = "warp")]
pub mod warp;

/// bee-rust（`bee_router`）的路由直接接收 axum handler，状态也走 axum 的
/// `State`，所以适配层就是 axum 那一层，这里只把文档与再导出处放好。
///
/// 需要留意的是：`bee_router` 里还有一套 Beego 风格的
/// `Filter`/`Controller`/`Context` 链路，但那套**没有**接到 `Router` 上 ——
/// 框架自己的示例与 admin 项目走的都是 `Router` + axum handler。所以这里提供
/// 的是 `Router` 路径的适配，`Filter` 路径要拿守卫得自己从 `Context` 里取。
/// feature 名是 `bee-rust`，模块名只能是 `bee_rust` —— Rust 标识符不允许连字符。
#[cfg(feature = "bee-rust")]
pub mod bee_rust {
    pub use super::Guarded;
    pub use super::axum::GuardExtractor;

    /// bee-rust 集成的用法要点（示例不参与编译，bee-rust 的路由构造需要真实状态）。
    ///
    /// ```text
    /// use encryptable::guard::Guard;
    /// use encryptable::integrations::Guarded;
    /// use bee_router::Router;
    ///
    /// #[derive(Clone)]
    /// struct AppState { encryption: Guard }
    /// impl Guarded for AppState {
    ///     fn guard(&self) -> &Guard { &self.encryption }
    /// }
    ///
    /// async fn health(guard: Guard) -> String {
    ///     format!("ring={}", guard.ring_len())
    /// }
    ///
    /// let app = Router::new()
    ///     .ns("/api/v1", |ns| ns.get("/health", health))
    ///     .with_state(AppState { encryption: guard });
    /// ```
    pub const USAGE: &str = "见本模块文档";
}

#[cfg(feature = "ecat")]
pub mod ecat;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use std::sync::Arc;

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    /// 最小场景：状态就是一把守卫，零样板。
    #[test]
    fn guard_is_itself_guarded() {
        let g = guard();
        assert_eq!(g.guard().ring_len(), 1);
    }

    #[test]
    fn arc_guard_is_guarded() {
        let g = Arc::new(guard());
        assert_eq!(g.guard().ring_len(), 1);
    }

    /// 真实场景：守卫是状态结构体的一个字段。
    #[test]
    fn a_larger_state_can_point_at_its_guard() {
        struct AppState {
            #[allow(dead_code)]
            pool: Arc<()>,
            encryption: Guard,
        }
        impl Guarded for AppState {
            fn guard(&self) -> &Guard {
                &self.encryption
            }
        }

        let state = AppState {
            pool: Arc::new(()),
            encryption: guard(),
        };

        let cipher = state.guard().encrypt("x").unwrap();
        assert_eq!(state.guard().decrypt_text(&cipher).unwrap(), "x");
    }
}
