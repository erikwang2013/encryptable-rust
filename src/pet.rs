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

/// 形象 SVG 的字节数。下游要给它留缓冲区时用得着。
pub const SVG_LEN: usize = SVG.len();

/// 形象的 MIME 类型。
///
/// 挂成 HTTP 端点时必须带上它 —— 少了这个头，浏览器会把它当成纯文本渲染，
/// 用户看到的是一屏 XML 而不是那只挂钥匙环的锁。
pub const CONTENT_TYPE: &str = "image/svg+xml";

/// SVG 形象，函数形式。
///
/// 与常量 [`SVG`] 是同一份东西，这个形式存在的意义是让调用点读起来像
/// PHP 版的 `Mascot::svg()`，也方便将来换成按需读取而不改动调用方。
///
/// ```
/// assert!(encryptable::pet::svg().starts_with("<svg"));
/// ```
pub fn svg() -> &'static str {
    SVG
}

/// 终端里的 ASCII 形象，函数形式（对应常量 [`ASCII`]）。
///
/// ```
/// assert!(encryptable::pet::ascii().contains("Locky"));
/// ```
pub fn ascii() -> &'static str {
    ASCII
}

/// 形象的数据 URI，可直接塞进 HTML 的 `<img src>`。
///
/// ```
/// let uri = encryptable::pet::data_uri();
/// assert!(uri.starts_with("data:image/svg+xml;base64,"));
/// ```
///
/// 做成数据 URI 而不是让调用方去读文件，是因为**下游不该依赖本 crate 的
/// 文件布局**：`docs/pet.svg` 会不会随包发布是本库自己的事，而数据 URI
/// 一定在二进制里 —— 它和 `SVG` 是同一份 `include_str!` 的结果。
///
/// 在框架处理器里挂一个「项目图标」端点：
///
/// ```
/// # #[cfg(feature = "axum")]
/// # mod demo {
/// use axum::response::Html;
///
/// async fn pet_icon() -> Html<String> {
///     Html(format!(
///         r#"<img src="{}" alt="Locky" width="64">"#,
///         encryptable::pet::data_uri()
///     ))
/// }
/// # }
/// ```
pub fn data_uri() -> String {
    use base64::Engine as _;
    const PREFIX: &str = "data:image/svg+xml;base64,";
    let mut out = String::with_capacity(PREFIX.len() + SVG.len().div_ceil(3) * 4);
    out.push_str(PREFIX);
    base64::engine::general_purpose::STANDARD.encode_string(SVG, &mut out);
    out
}

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

    /// 函数形式与常量形式必须是同一份东西 —— 两条路给出不同图片就麻烦了。
    #[test]
    fn accessors_agree_with_the_constants() {
        assert_eq!(svg(), SVG);
        assert_eq!(ascii(), ASCII);
        assert_eq!(SVG_LEN, SVG.len());
    }

    /// 数据 URI 必须能原样解回 SVG。
    ///
    /// 这条是关键：base64 编错一个字节，图片就是坏的，而坏掉的图在
    /// HTML 里表现为「什么都不显示」，不会报任何错。
    #[test]
    fn data_uri_decodes_back_to_the_svg() {
        use base64::Engine as _;

        let uri = data_uri();
        let payload = uri
            .strip_prefix("data:image/svg+xml;base64,")
            .expect("前缀不对 —— HTML 认不出这个 URI");

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .expect("载荷不是合法 base64");

        assert_eq!(decoded, SVG.as_bytes(), "解回来的字节与 SVG 不一致");
        assert_eq!(String::from_utf8(decoded).unwrap(), SVG);
    }

    /// 数据 URI 里不能有换行或空白 —— 那会让 `src="..."` 断掉。
    #[test]
    fn data_uri_is_a_single_clean_token() {
        let uri = data_uri();
        assert!(!uri.contains('\n'), "数据 URI 含换行");
        assert!(!uri.contains(' '), "数据 URI 含空格");
        assert!(uri.is_ascii(), "数据 URI 含非 ASCII 字符");
    }

    /// 容量估算不能算少（`with_capacity` 少了只是重新分配，但说明算式错了）。
    #[test]
    fn data_uri_capacity_estimate_is_not_short() {
        let uri = data_uri();
        // base64 膨胀到 4/3 并向上取整，再加前缀
        let expected = "data:image/svg+xml;base64,".len() + SVG.len().div_ceil(3) * 4;
        assert!(
            uri.len() <= expected,
            "实际 {} 字节，估算上界 {} 字节",
            uri.len(),
            expected
        );
    }
}
