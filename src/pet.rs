// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 项目宠物：**Locky · 小锁灵**。
//!
//! 本模块不含逻辑，只有形象本身 —— README、CLI banner、下游管理界面共用同一份。
//! 形象文件在 `docs/pet.svg`，终端里用 [`ASCII`]。
//!
//! ```text
//!          .--.
//!         /    \        Locky · 小锁灵
//!        _|    |_
//!       |        |      琥珀钥匙 = 主密钥
//!       |  o  o  |      两把灰钥匙 = previous_keys
//!       |    ^   |      锁扣 = AEAD tag
//!       |________|
//! ```
//!
//! 人设取自本库的密钥轮换模型：钥匙环上那把**琥珀色**的是当前主密钥，两把
//! **灰色**的是 `previous_keys` —— 它们还在环上、还能解开旧密文，直到你主动退役。
//! 锁扣上的「AEAD」徽章是应用侧的认证 tag。纯装饰：这里没有任何一行碰得到密钥、
//! 密码或载荷。

/// 项目宠物名。
pub const NAME: &str = "Locky · 小锁灵";

/// 一句话人设。
pub const TAGLINE: &str = "钥匙还在环上，旧密文就还解得开";

/// ASCII 版形象，给终端、日志、CLI banner 用。
pub const ASCII: &str = r#"         .--.
        /    \        Locky · 小锁灵
       _|    |_
      |        |      琥珀钥匙 = 主密钥
      |  o  o  |      两把灰钥匙 = previous_keys
      |    ^   |      锁扣 = AEAD tag
      |________|"#;

/// SVG 版形象（`docs/pet.svg`），给 README 与下游界面用。
///
/// 以 `include_str!` 打进库里：零运行时开销，不用就不链接。
/// 也正因如此 `docs/pet.svg` **不能**进 Cargo 的 `exclude` —— 排掉会当场编译失败。
pub const SVG: &str = include_str!("../docs/pet.svg");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_is_bundled_whole() {
        assert!(
            SVG.starts_with("<svg"),
            "SVG 头部: {:?}",
            &SVG[..40.min(SVG.len())]
        );
        assert!(SVG.trim_end().ends_with("</svg>"));
        assert!(SVG.contains(r#"viewBox="0 0 320 360""#), "viewBox 变了");
    }

    /// 形象与库的对账：环上三把钥匙 = 主密钥 + 两把退役密钥，
    /// 这正是 `KeyRing` 讲的那个故事。数画法不数颜色 —— 改配色、改坐标
    /// 不该让这里变红。
    #[test]
    fn key_ring_art_matches_the_rotation_model() {
        // 两把灰钥匙（previous_keys），每把由「钥匙头 + 两齿」共 4 个形状组成
        assert_eq!(
            SVG.matches("fill=\"#94A3B8\"").count(),
            8,
            "灰钥匙的形状数变了"
        );
        // 环上两把灰钥匙各自旋开一个角度，金钥匙居中
        assert_eq!(SVG.matches("transform=\"rotate(-30 160 94)\"").count(), 1);
        assert_eq!(SVG.matches("transform=\"rotate(30 160 94)\"").count(), 1);
        // 一把金钥匙（主密钥）
        assert_eq!(
            SVG.matches("url(#keyGold)").count(),
            2,
            "主密钥的金色渐变没了"
        );
        assert!(SVG.contains("Locky · 小锁灵"), "形象上的铭牌没了");
    }

    #[test]
    fn ascii_and_name_are_not_empty() {
        assert!(!NAME.is_empty() && !TAGLINE.is_empty());
        assert!(ASCII.lines().count() >= 6, "ASCII 形象太短");
        assert!(ASCII.contains("Locky"));
    }
}
