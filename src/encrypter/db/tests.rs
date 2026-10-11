// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 本模块的单元测试。

use super::*;
use crate::config::ArrayConfig;

const K1: &str = "0123456789abcdef0123456789abcdef";
const K16: &str = "0123456789abcdef";

/// 金标量用的主密钥（它本身就是 64 个 hex 字符）。
const GOLDEN_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// `GOLDEN_KEY` 经 HKDF-SHA256（info = "encryptable-rust/db-ecb/v1"）派生的
/// DB 侧子密钥。由 Python `cryptography` 独立复算，openssl 交叉验证过。
const GOLDEN_DERIVED: &str = "a17d9e28145951c875300f13a955288579cf74000125e8eba07772a507db8f94";

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
    assert_eq!(e.key_hex().len(), 32, "主密钥 hex 是 32 字符");
    assert_eq!(e.derived_key_hex().len(), 32, "子密钥 hex 也是 32 字符");
    assert_ne!(e.derived_key_hex().as_str(), e.key_hex().as_str());
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
    let d = plain_db();

    // 当前格式（0x03）与旧格式（0x01）的真载荷都拦
    let app_payload = app.seal("x").unwrap();
    assert!(matches!(
        d.encrypt(&app_payload),
        Err(Error::WrongFormat {
            found: 0x03,
            expected: 0x04
        })
    ));
    assert!(matches!(
        d.decrypt(&app_payload),
        Err(Error::WrongFormat {
            found: 0x03,
            expected: 0x04
        })
    ));

    // 手工造一段 0x01 旧载荷：首字节 0x01 + 足够长度，形状判定的长度闸放行
    let mut fake = vec![crate::encrypter::aead::LEGACY_VERSION];
    fake.extend_from_slice(&[0u8; 40]);
    let legacy = base64::engine::general_purpose::STANDARD.encode(&fake);
    assert!(matches!(
        d.encrypt(&legacy),
        Err(Error::WrongFormat {
            found: 0x01,
            expected: 0x04
        })
    ));
}

/// `AQ`/`AR`/`AS`/`AT` 开头的合法 base64 明文（首字节恒为 0x01，由前两个字符
/// 唯一决定）曾经被形状判定**永久误拒**，而且 DB 侧没有绕过口。
/// 长度闸（真应用侧载荷恒 ≥ 40 字符）之后，短输入必须能正常加密。
#[test]
fn short_lookalike_plaintext_is_no_longer_rejected() {
    let e = plain_db();
    for s in [
        "AQ0123456789012345678901",     // 24 字符，解出首字节 0x01
        "ATabcdefghijklmnopqrstuv",     // 同上
        "AQ00000000000000000000000000", // 28 字符
    ] {
        let c = e.encrypt(s).unwrap();
        assert_eq!(e.decrypt(&c).unwrap(), s, "{s:?} 应当能被加密并往返");
    }
}

/// 形状判定对长输入仍有假阳性上限（48 字符的 `AQ…` 照样误拦）——
/// 绕过口是 `seal()`，这里把两条路都钉住。
#[test]
fn seal_is_the_unconditional_escape_hatch() {
    let e = plain_db();
    let long_lookalike = format!("AQ{}", "0".repeat(46));
    assert!(matches!(
        e.encrypt(&long_lookalike),
        Err(Error::WrongFormat { found: 0x01, .. })
    ));

    let c = e.seal(&long_lookalike).unwrap();
    assert_eq!(e.decrypt(&c).unwrap(), long_lookalike);

    // 真应用侧载荷同理：encrypt 拦，seal 放行
    use crate::encrypter::AeadEncrypter;
    let app = AeadEncrypter::new(&ArrayConfig::new(K1)).unwrap();
    let payload = app.seal("x").unwrap();
    assert!(e.encrypt(&payload).is_err());
    let c = e.seal(&payload).unwrap();
    assert_eq!(e.decrypt(&c).unwrap(), payload);
}

/// 当前格式必须用 HKDF 子密钥加密 —— 主密钥原样解不开。
/// 这条是密钥分离在 DB 侧的核心断言：E_K(·) 预言机已不对外。
#[test]
fn current_format_uses_the_derived_subkey() {
    let e = plain_db();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(e.encrypt("hello").unwrap())
        .unwrap();
    let ct = &raw[1..];

    // 子密钥解密：拿回明文
    let mut via_sub = ct.to_vec();
    e.current.decrypt_blocks(&mut via_sub);
    assert_eq!(pkcs7_unpad(&via_sub).unwrap(), b"hello");

    // 主密钥原样解密：拿不回 "hello"（要么补位错，要么乱码）
    let mut via_master = ct.to_vec();
    e.legacy.decrypt_blocks(&mut via_master);
    assert_ne!(
        pkcs7_unpad(&via_master).unwrap_or_default(),
        &b"hello"[..],
        "当前格式不该是主密钥直接加密的（否则 ECB 预言机又能击穿 GCM）"
    );
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

/// 解密之后的失败只有**一条**消息 —— 补位长度错、补位字节不自洽、UTF-8 非法
/// 三者不可区分，与「密钥错」也不可区分。可区分的失败就是 padding oracle：
/// 逐字节改密文、看错误分类，能还原 `D_K(·)`。这条钉住折叠后的出口。
#[test]
fn post_decryption_failures_are_indistinguishable() {
    let e = plain_db();
    let b64 = |v: &[u8]| base64::engine::general_purpose::STANDARD.encode(v);

    // 造三段密文：补位长度非法、补位不自洽、UTF-8 非法。
    // 直接手工构造「解密后」的块 —— 这里关心的是 decrypt 的出口文案。
    let mut msgs = Vec::new();

    // ① 合法密文但补位字节被改成非法值：解出来的块末字节 = 0 是不可达的
    //    —— 换个构造法：拿真密文、翻转最后一字节，多试几个直到进入后解密失败分支
    let raw = base64::engine::general_purpose::STANDARD
        .decode(e.encrypt("aaaaaaaaaaaaaaaa").unwrap())
        .unwrap();
    for flip in 0u8..32 {
        let mut bad = raw.clone();
        let last = bad.len() - 1;
        bad[last] ^= flip;
        match e.decrypt(&b64(&bad)) {
            // 形状层失败（版本/长度）不算数，要的是「解出来但校验不过」
            Err(Error::Decrypt(m)) if !m.contains("字节") => msgs.push(m),
            _ => continue,
        }
    }
    assert!(!msgs.is_empty(), "至少要能构造出一种后解密失败");
    let first = &msgs[0];
    for m in &msgs {
        assert_eq!(m, first, "后解密失败的消息必须只有一种：{msgs:?}");
    }
    assert!(!first.contains("补位长度"), "消息不该区分具体原因：{first}");
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

/// 片段里不得出现单引号 —— 密钥走 hex 之后，整条语句的字符串字面量
/// 只剩 `'UTF8'` / `'base64'` / `'aes-ecb'` 这三个固定常量。
#[test]
fn fragments_never_quote_the_key() {
    let e = plain_db();
    for driver in [DbDriver::Mysql, DbDriver::Postgres] {
        let sql = e.decrypt_expr("phone", driver).unwrap();
        assert!(!sql.contains(K1), "密钥明文出现在了 SQL 里");

        let master = e.key_hex();
        let master = master.as_str();
        let derived = e.derived_key_hex();
        let derived = derived.as_str();
        // 迁移期两代密钥都在 CASE 里，都必须是纯 hex
        assert!(sql.contains(master), "主密钥应当以 hex 形式出现");
        assert!(sql.contains(derived), "子密钥应当以 hex 形式出现");
        assert!(
            master.chars().all(|c| c.is_ascii_hexdigit())
                && derived.chars().all(|c| c.is_ascii_hexdigit()),
            "密钥含非 hex 字符"
        );

        // 引号只包住固定常量与那两串 hex。PG 的 bytea 字面量比 MySQL 多一个
        // `\x` 前缀，剥掉之后应当正好是某个 hex。
        for quoted in sql.split('\'').skip(1).step_by(2) {
            let bare = quoted.strip_prefix("\\x").unwrap_or(quoted);
            assert!(
                matches!(bare, "UTF8" | "base64" | "aes-ecb") || bare == master || bare == derived,
                "意外的引号内容: {quoted:?}"
            );
        }
    }
}

/// 片段全文逐字符钉死 —— 两种方言各一条（CASE 按格式字节分派两代密钥）。
#[test]
fn fragment_shapes_are_stable() {
    let e = db(GOLDEN_KEY, "aes-256-ecb");
    let current = GOLDEN_DERIVED;
    let legacy = GOLDEN_KEY;
    assert_eq!(
        e.decrypt_expr("phone", DbDriver::Mysql).unwrap(),
        format!(
            "CASE SUBSTRING( FROM_BASE64(phone), 1, 1 ) WHEN 0x04 THEN CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64(phone), 2 ), UNHEX('{current}') ) USING 'UTF8' ) WHEN 0x02 THEN CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64(phone), 2 ), UNHEX('{legacy}') ) USING 'UTF8' ) ELSE NULL END"
        )
    );
    assert_eq!(
        e.decrypt_expr("phone", DbDriver::Postgres).unwrap(),
        format!(
            "CASE get_byte( decode(phone, 'base64'), 0 ) WHEN 4 THEN convert_from( decrypt( substring( decode(phone, 'base64') from 2 ), '\\x{current}'::bytea, 'aes-ecb' ), 'UTF8' ) WHEN 2 THEN convert_from( decrypt( substring( decode(phone, 'base64') from 2 ), '\\x{legacy}'::bytea, 'aes-ecb' ), 'UTF8' ) ELSE NULL END"
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

/// 1.2.x 时代的金标量（0x02，主密钥直用，与 OpenSSL 逐字节一致，向量由
/// `printf 'hello' | openssl enc -aes-256-ecb -K 000102…1f -nosalt` 产生，
/// 补版本字节 0x02 再 base64）。
///
/// 现在它们不再是 `encrypt()` 的输出，但**必须照旧解得出** —— 双读的回归锚。
#[test]
fn legacy_0x02_openssl_vectors_still_decrypt() {
    let e = db(GOLDEN_KEY, "aes-256-ecb");

    let vectors = [
        ("hello", "ApFoRIfDTDRW606QHO+ISh4="),
        ("", "Ap87dQSSb4vTbjEY6QOkzUo="),
        ("13800138000", "AoQ6gYBRYrnicYSeTd+q4JE="),
        (
            "0123456789abcdef",
            "AtjJV1jjNT5TD6Ur0Q5zuYafO3UEkm+L024xGOkDpM1K",
        ),
        (
            "0123456789abcdefg",
            "AtjJV1jjNT5TD6Ur0Q5zuYaUYIJThm4Mk92aTtRFyV6M",
        ),
    ];

    for (plain, payload) in vectors {
        assert!(e.is_encrypted(payload), "旧格式应当被形状判定认下");
        assert_eq!(
            e.decrypt(payload).unwrap(),
            plain,
            "{payload} 解不回 {plain:?}"
        );
    }

    // 新写入一律是 0x04 —— 旧格式不再产生
    let fresh = base64::engine::general_purpose::STANDARD
        .decode(e.encrypt("hello").unwrap())
        .unwrap();
    assert_eq!(fresh[0], VERSION);
}

/// 当前格式（0x04，HKDF 子密钥）的金标量：由 Python `cryptography` 的
/// HKDF + AES-ECB 独立复算，并用 `openssl enc -aes-256-ecb -K <子密钥> -nosalt`
/// 交叉验证逐字节一致。
#[test]
fn current_0x04_vectors_match_an_independent_implementation() {
    let e = db(GOLDEN_KEY, "aes-256-ecb");

    let vectors = [
        ("hello", "BOYYaq3EaFHu/6Yixg7q078="),
        ("", "BO+AOag1nymSPNWvngLiFek="),
        ("13800138000", "BO+95MZeXhnkDI755gKz+LY="),
        (
            "0123456789abcdef",
            "BGYbjibR2840U5GdEdY9dxTvgDmoNZ8pkjzVr54C4hXp",
        ),
        (
            "0123456789abcdefg",
            "BGYbjibR2840U5GdEdY9dxQqDAa7Srxc1vvZaADmFYAn",
        ),
    ];

    for (plain, expected) in vectors {
        assert_eq!(
            e.encrypt(plain).unwrap(),
            expected,
            "明文 {plain:?} 与独立实现不一致"
        );
        assert_eq!(e.decrypt(expected).unwrap(), plain);
    }
}

/// AES-128 的子密钥派生与加密金标量（同一套 Python/openssl 双复算）。
#[test]
fn current_0x04_aes128_vector() {
    let e = db("000102030405060708090a0b0c0d0e0f", "aes-128-ecb");
    assert_eq!(
        e.derived_key_hex().as_str(),
        "e2cbb14c7f24e9912e0c38b2ab2a60a0"
    );
    assert_eq!(e.encrypt("hi").unwrap(), "BDZk7JlwwapMB88gKcFUQKg=");
    assert_eq!(e.decrypt("BDZk7JlwwapMB88gKcFUQKg=").unwrap(), "hi");
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
