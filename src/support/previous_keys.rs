// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 把 `ENCRYPTION_PREVIOUS_KEYS` 这类字符串拆成一组退役密钥。

use crate::error::{Error, Result};

/// 拆分逗号分隔的密钥列表。
///
/// 每一项都会 trim，空项直接丢掉（`a,,b` 与 `a, b` 等价，尾随逗号不算错）。
///
/// **JSON 数组会被显式拒绝**，这与 PHP 版不同 —— PHP 是照单全收的。原因是
/// `["k1","k2"]` 若按逗号硬拆会得到 `["k1"` 和 `"k2"]` 两把**错的**密钥，而错密钥
/// 在密钥环里是**静默失效**的：解密会跳过它继续试下一把，最后只报一句「全都失败」，
/// 没人看得出真正原因是配置格式。宁可在读配置时就炸。
pub fn parse(raw: &str) -> Result<Vec<String>> {
    let raw = raw.trim();

    if raw.is_empty() {
        return Ok(Vec::new());
    }

    if raw.starts_with('[') {
        return Err(Error::Serialize(
            "previous_keys 不接受 JSON 数组，请改用逗号分隔，例如 k1,k2,k3".into(),
        ));
    }

    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_inputs_yield_no_keys() {
        for raw in ["", "   ", ",", ",,", " , , "] {
            assert_eq!(parse(raw).unwrap(), Vec::<String>::new(), "{raw:?}");
        }
    }

    #[test]
    fn splits_trims_and_drops_blanks() {
        let got = parse("k1, k2 ,,k3,").unwrap();
        assert_eq!(got, vec!["k1", "k2", "k3"]);
    }

    #[test]
    fn single_key_is_fine() {
        assert_eq!(parse("only").unwrap(), vec!["only"]);
    }

    /// 这条是刻意与 PHP 版分道扬镳的地方，得钉住。
    #[test]
    fn json_arrays_are_rejected_loudly() {
        for raw in [r#"["k1","k2"]"#, "[k1,k2]", "[]"] {
            let err = parse(raw).unwrap_err();
            assert!(err.to_string().contains("逗号分隔"), "{raw:?} → {err}");
        }
    }

    /// 密钥里本来就可能含空格，只有逗号是分隔符。
    #[test]
    fn inner_commas_still_split_but_spaces_survive() {
        assert_eq!(
            parse("key one,key two").unwrap(),
            vec!["key one", "key two"]
        );
    }
}
