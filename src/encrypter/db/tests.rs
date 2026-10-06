// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 本模块的单元测试。

use super::*;
use crate::config::ArrayConfig;

const K1: &str = "0123456789abcdef0123456789abcdef";
const K16: &str = "0123456789abcdef";

fn db(key: &str, cipher: &str) -> DbEncrypter {
    DbEncrypter::new(&ArrayConfig::new(key).with_cipher(cipher)).unwrap()
}

fn plain_db() -> DbEncrypter {
    db(K1, "aes-256-ecb")
}

#[test]
fn round_trips_text() {
    let e = plain_db();
    for s in ["", "hello", "世界", "a", &"x".repeat(1000)] {
        let c = e.encrypt(s).unwrap();
        assert_eq!(e.decrypt(&c).unwrap(), s, "{s:?} 往返不一致");
    }
}

/// 这就是这条路径存在的理由：同明文恒定产出同密文。
#[test]
fn encryption_is_deterministic() {
    let e = plain_db();
    assert_eq!(
        e.encrypt("13800138000").unwrap(),
        e.encrypt("13800138000").unwrap()
    );
    assert_ne!(
        e.encrypt("13800138000").unwrap(),
        e.encrypt("13800138001").unwrap()
    );
}

/// 应用侧是反过来的 —— 同一个库里的两条路径得有不同性质，别搞混。
#[test]
fn app_side_is_not_deterministic_but_db_side_is() {
    use crate::encrypter::AeadEncrypter;
    let app = AeadEncrypter::new(&ArrayConfig::new(K1)).unwrap();
    assert_ne!(app.seal("x").unwrap(), app.seal("x").unwrap());
    let d = plain_db();
    assert_eq!(d.encrypt("x").unwrap(), d.encrypt("x").unwrap());
}

#[test]
fn padded_lengths_are_exact() {
    let e = plain_db();
    // 1 字节版本 + 密文，密文永远是 16 的整数倍
    for len in [0, 1, 15, 16, 17, 31, 32, 33] {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(e.encrypt(&"a".repeat(len)).unwrap())
            .unwrap();
        assert_eq!(
            raw.len(),
            1 + (len / BLOCK + 1) * BLOCK,
            "明文 {len} 字节时长度不对"
        );
        assert_eq!(raw[0], VERSION);
    }
}

#[test]
fn wrong_key_yields_wrong_or_garbage_not_silence() {
    let a = plain_db();
    let b = db("fedcba9876543210fedcba9876543210", "aes-256-ecb");
    let c = a.encrypt("secret").unwrap();
    // 期望解出的不是原文（大概率报错，小概率是乱码）
    assert_ne!(b.decrypt(&c).unwrap_or_default(), "secret");
}

#[test]
fn aes_128_ecb_works() {
    let e = db(K16, "aes-128-ecb");
    assert_eq!(e.cipher_name(), "aes-128-ecb");
    assert_eq!(e.decrypt(&e.encrypt("hi").unwrap()).unwrap(), "hi");
}

#[test]
fn non_deterministic_cipher_is_refused_at_construction() {
    for c in ["aes-256-gcm", "aes-128-gcm", "aes-256-cbc"] {
        assert!(
            matches!(
                DbEncrypter::new(&ArrayConfig::new(K1).with_cipher(c)),
                Err(Error::CipherNotUsable { .. })
            ),
            "{c} 不该被 DB 侧接受"
        );
    }
}

#[test]
fn rejects_app_side_payloads_instead_of_double_encrypting() {
    use crate::encrypter::AeadEncrypter;
    let app = AeadEncrypter::new(&ArrayConfig::new(K1)).unwrap();
    let app_payload = app.seal("x").unwrap();

    let d = plain_db();
    assert!(matches!(
        d.encrypt(&app_payload),
        Err(Error::WrongFormat {
            found: 0x01,
            expected: 0x02
        })
    ));
    assert!(matches!(
        d.decrypt(&app_payload),
        Err(Error::WrongFormat {
            found: 0x01,
            expected: 0x02
        })
    ));
}

#[test]
fn is_encrypted_shape_check() {
    let e = plain_db();
    assert!(e.is_encrypted(&e.encrypt("x").unwrap()));
    assert!(!e.is_encrypted("plain"));
    assert!(!e.is_encrypted(""));
    assert!(!e.is_encrypted(&base64::engine::general_purpose::STANDARD.encode([VERSION; 5])));
}

#[test]
fn pkcs7_pads_and_unpads_at_the_boundary() {
    for len in [0, 1, 15, 16, 17, 31, 32, 33] {
        let data = vec![0xABu8; len];
        let padded = pkcs7_pad(&data);
        assert_eq!(padded.len() % BLOCK, 0);
        assert!(padded.len() > len, "对齐时也必须补满一整块");
        assert_eq!(pkcs7_unpad(&padded).unwrap(), &data[..]);
    }
}

#[test]
fn pkcs7_unpad_rejects_malformed_padding() {
    assert!(pkcs7_unpad(&[]).is_err());
    // 补位字节说 0
    assert!(pkcs7_unpad(&[0u8; 16]).is_err());
    // 补位字节说 17
    assert!(pkcs7_unpad(&[17u8; 16]).is_err());
    // 说补 3 个但尾部字节不一致
    let mut bad = vec![0u8; 13];
    bad.extend_from_slice(&[3, 3, 9]);
    assert!(pkcs7_unpad(&bad).is_err());
}

#[test]
fn column_guard_accepts_plain_and_qualified_names() {
    for ok in [
        "phone",
        "_x1",
        "users.phone",
        "a.b.c",
        "A9",
        &"a".repeat(63),
    ] {
        assert!(validate_column(ok).is_ok(), "{ok:?} 应当被接受");
    }
}

#[test]
fn column_guard_rejects_injection_shapes() {
    for bad in [
        "",
        "1phone",
        ".a",
        "a.b.",
        "phone; DROP TABLE users",
        "phone)",
        "phone p",
        "\"phone\"",
        "phone'",
        "phone--",
        "пользователь",
        &"a".repeat(64),
    ] {
        assert!(validate_column(bad).is_err(), "{bad:?} 应当被拒绝");
    }
}

/// 片段里不得出现单引号 —— 密钥改走 hex 之后，整条语句的字符串字面量
/// 只剩 `'UTF8'` / `'base64'` / `'aes-ecb'` 这三个固定常量。
#[test]
fn fragments_never_quote_the_key() {
    let e = plain_db();
    for driver in [DbDriver::Mysql, DbDriver::Postgres] {
        let sql = e.decrypt_expr("phone", driver).unwrap();
        assert!(!sql.contains(K1), "密钥明文出现在了 SQL 里");
        let hex = e.key_hex();
        let hex = hex.as_str();
        assert!(sql.contains(hex), "密钥应当以 hex 形式出现");

        // 真正要守的不变量：密钥只以**纯十六进制**进入 SQL。十六进制字符集里
        // 没有引号，它不可能从字符串字面量（`UNHEX('…')`）里逃出去 ——
        // 这正是这里不再需要 escapeSqlString() 的原因。
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "密钥含非 hex 字符"
        );

        // 引号只包住固定常量与那串 hex。PG 的 bytea 字面量比 MySQL 多一个
        // `\x` 前缀，剥掉之后应当正好是 hex 本身。
        for quoted in sql.split('\'').skip(1).step_by(2) {
            let bare = quoted.strip_prefix("\\x").unwrap_or(quoted);
            assert!(
                matches!(bare, "UTF8" | "base64" | "aes-ecb") || bare == hex,
                "意外的引号内容: {quoted:?}"
            );
        }
    }
}

#[test]
fn fragment_shapes_are_stable() {
    let e = plain_db();
    let hex = e.key_hex();
    let hex = hex.as_str();
    assert_eq!(
        e.decrypt_expr("phone", DbDriver::Mysql).unwrap(),
        format!(
            "CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64(phone), 2 ), UNHEX('{hex}') ) USING 'UTF8' )"
        )
    );
    assert_eq!(
        e.decrypt_expr("phone", DbDriver::Postgres).unwrap(),
        format!(
            "convert_from( decrypt( substring( decode(phone, 'base64') from 2 ), '\\x{hex}'::bytea, 'aes-ecb' ), 'UTF8' )"
        )
    );
}

#[test]
fn fragment_rejects_bad_columns() {
    let e = plain_db();
    assert!(matches!(
        e.decrypt_expr("phone; DROP TABLE users", DbDriver::Mysql),
        Err(Error::InvalidColumnRef(_))
    ));
}

#[test]
fn driver_defaults_come_from_config() {
    let e = DbEncrypter::new(
        &ArrayConfig::new(K1)
            .with_cipher("aes-256-ecb")
            .with_db_driver(DbDriver::Postgres),
    )
    .unwrap();
    assert_eq!(e.driver(), DbDriver::Postgres);
    assert!(
        e.decrypt_expr_default("phone")
            .unwrap()
            .contains("pgcrypto")
            .eq(&false)
    );
    assert!(
        e.decrypt_expr_default("phone")
            .unwrap()
            .contains("convert_from")
    );
}

/// 金标量：手写的 PKCS#7 + ECB 必须与 OpenSSL 逐字节一致。
///
/// 这是「数据库能不能读懂我们写的字节」唯一能在 CI 里验证的代理 ——
/// 真跑 MySQL / pgcrypto 需要数据库，见 `tests/db_sql.rs` 里那个 `#[ignore]` 的测试。
///
/// 向量由下面这条命令产生（明文按需替换）：
///
/// ```text
/// printf 'hello' | openssl enc -aes-256-ecb -K 000102…1f -nosalt | base64 -w0
/// ```
///
/// 补上版本字节 `0x02` 再 base64 就是下表的值。
#[test]
fn matches_openssl_byte_for_byte() {
    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let e = db(KEY, "aes-256-ecb");

    let vectors = [
        ("hello", "ApFoRIfDTDRW606QHO+ISh4="),
        ("", "Ap87dQSSb4vTbjEY6QOkzUo="),
        ("13800138000", "AoQ6gYBRYrnicYSeTd+q4JE="),
        // 正好 16 字节：PKCS#7 仍要补满一整块，所以密文是两个块
        (
            "0123456789abcdef",
            "AtjJV1jjNT5TD6Ur0Q5zuYafO3UEkm+L024xGOkDpM1K",
        ),
        (
            "0123456789abcdefg",
            "AtjJV1jjNT5TD6Ur0Q5zuYaUYIJThm4Mk92aTtRFyV6M",
        ),
    ];

    for (plain, expected) in vectors {
        assert_eq!(
            e.encrypt(plain).unwrap(),
            expected,
            "明文 {plain:?} 与 OpenSSL 不一致"
        );
        assert_eq!(
            e.decrypt(expected).unwrap(),
            plain,
            "{expected} 解不回 {plain:?}"
        );
    }
}

/// 对齐时补满整块这件事，单独钉一条 —— 少补一个块会让「16 字节的明文」
/// 与「15 字节的明文」在库里产生同样的密文长度，去位时无从分辨。
#[test]
fn aligned_input_gets_a_whole_extra_block() {
    let e = plain_db();
    let raw = |s: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(e.encrypt(s).unwrap())
            .unwrap()
    };
    assert_eq!(raw("0123456789abcdef").len(), 1 + 2 * BLOCK);
    assert_eq!(raw("0123456789abcde").len(), 1 + BLOCK);
}

/// 密钥不该从 `Debug` 里漏出去。
#[test]
fn debug_never_leaks_the_key() {
    let e = plain_db();
    let s = format!("{e:?}");
    assert!(!s.contains(K1), "{s}");
}
