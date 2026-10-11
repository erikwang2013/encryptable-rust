// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 本模块的单元测试。

use super::*;
use crate::cipher::Cipher;
use crate::config::ArrayConfig;
use crate::key::Key;
use crate::support::subkeys;

const K1: &str = "0123456789abcdef0123456789abcdef";
const K2: &str = "fedcba9876543210fedcba9876543210";
const K16: &str = "0123456789abcdef";

fn enc(key: &str) -> AeadEncrypter {
    AeadEncrypter::new(&ArrayConfig::new(key)).unwrap()
}

/// 手工构造一段 1.2.x 时代的 `0x01` 载荷：主密钥直用，AAD 只有版本字节。
/// 用于钉住双读 —— 旧数据升级后必须照旧解得开。
fn legacy_payload(key: &str, text: &str) -> String {
    let raw_key = Key::parse(key, Cipher::Aes256Gcm).unwrap();
    let gcm = Aes256Gcm::new_from_slice(raw_key.as_bytes()).unwrap();
    let nonce = [0x5Au8; NONCE_LEN];
    let plaintext = Value::String(text.into()).encode();
    let ct = gcm
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &[LEGACY_VERSION],
            },
        )
        .unwrap();

    let mut payload = vec![LEGACY_VERSION];
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ct);
    base64::engine::general_purpose::STANDARD.encode(&payload)
}

#[test]
fn round_trips_every_scalar_type() {
    let e = enc(K1);
    for v in [
        Value::String("hello 世界".into()),
        Value::String(String::new()),
        Value::Int(-42),
        Value::Float(1.5),
        Value::Bool(true),
        Value::Bool(false),
        Value::Null,
    ] {
        let c = e.seal(v.clone()).unwrap();
        assert_eq!(e.decrypt(&c).unwrap(), v, "{v:?} 往返不一致");
    }
}

#[test]
fn same_plaintext_yields_different_ciphertexts() {
    let e = enc(K1);
    let a = e.seal("same").unwrap();
    let b = e.seal("same").unwrap();
    assert_ne!(a, b, "nonce 应当随机");
    assert_eq!(e.decrypt_text(&a).unwrap(), e.decrypt_text(&b).unwrap());
}

#[test]
fn wrong_key_cannot_decrypt() {
    let a = enc(K1);
    let b = enc(K2);
    let c = a.seal("secret").unwrap();
    assert!(matches!(b.decrypt(&c), Err(Error::Decrypt(_))));
}

#[test]
fn tampering_is_detected() {
    let e = enc(K1);
    let c = e.seal("secret").unwrap();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(&c)
        .unwrap();
    // 翻掉密文里最后一个字节（tag 的一部分）
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    let tampered = base64::engine::general_purpose::STANDARD.encode(&raw);
    assert!(matches!(e.decrypt(&tampered), Err(Error::Decrypt(_))));
}

#[test]
fn every_single_byte_flip_is_caught() {
    let e = enc(K1);
    let raw = base64::engine::general_purpose::STANDARD
        .decode(e.seal("secret payload").unwrap())
        .unwrap();
    for i in 0..raw.len() {
        let mut bad = raw.clone();
        bad[i] ^= 0x80;
        let s = base64::engine::general_purpose::STANDARD.encode(&bad);
        assert!(e.decrypt(&s).is_err(), "翻转第 {i} 字节后仍能解开");
    }
}

#[test]
fn previous_key_still_decrypts_after_rotation() {
    let old = enc(K1);
    let cipher = old.seal("legacy row").unwrap();

    let rotated =
        AeadEncrypter::new(&ArrayConfig::new(K2).with_previous_keys(vec![K1.into()])).unwrap();

    assert_eq!(rotated.decrypt_text(&cipher).unwrap(), "legacy row");
    assert_eq!(rotated.ring_len(), 2);
}

#[test]
fn rotate_reencrypts_under_the_primary_key() {
    let old = enc(K1);
    let cipher = old.seal("row").unwrap();

    let rotated =
        AeadEncrypter::new(&ArrayConfig::new(K2).with_previous_keys(vec![K1.into()])).unwrap();

    let moved = rotated.rotate_to_current_key(&cipher).unwrap();
    assert_ne!(moved, cipher);

    // 只用新主密钥也能解开 —— 说明真的搬过去了
    let only_new = enc(K2);
    assert_eq!(only_new.decrypt_text(&moved).unwrap(), "row");
    // 旧密钥已经解不开它
    assert!(old.decrypt(&moved).is_err());
}

#[test]
fn rotate_leaves_plaintext_untouched() {
    let e = enc(K1);
    assert_eq!(
        e.rotate_to_current_key("not encrypted").unwrap(),
        "not encrypted"
    );
}

#[test]
fn encrypt_does_not_double_wrap() {
    let e = enc(K1);
    let once = e.encrypt("hi").unwrap();
    let twice = e.encrypt(once.as_str()).unwrap();
    assert_eq!(once, twice);
}

/// PHP 版的坑：一段 base64 解出来首字节恰好是格式字节的**明文**会被误判成密文
/// 然后直接存库。这里因为真的试了一次认证，它会照常被加密。
#[test]
fn plaintext_that_looks_like_ciphertext_is_still_encrypted() {
    let e = enc(K1);
    let mut fake = vec![VERSION];
    fake.extend_from_slice(&[0u8; 40]);
    let looks_encrypted = base64::engine::general_purpose::STANDARD.encode(&fake);

    assert!(e.is_encrypted(&looks_encrypted), "形状判定应当为真");
    let out = e.encrypt(looks_encrypted.as_str()).unwrap();
    assert_ne!(out, looks_encrypted, "但它并不真的能解开，所以必须被加密");
    assert_eq!(e.decrypt_text(&out).unwrap(), looks_encrypted);
}

#[test]
fn is_encrypted_rejects_non_ciphertext() {
    let e = enc(K1);
    assert!(!e.is_encrypted("plain"));
    assert!(!e.is_encrypted(""));
    // 合法 base64 但太短
    assert!(!e.is_encrypted(&base64::engine::general_purpose::STANDARD.encode([1u8; 5])));
    // 够长但版本字节不对
    assert!(!e.is_encrypted(&base64::engine::general_purpose::STANDARD.encode([0x09u8; 40])));
}

#[test]
fn db_payloads_are_rejected_by_name() {
    let e = enc(K1);
    for version in [
        crate::encrypter::DbEncrypter::VERSION,
        crate::encrypter::DbEncrypter::LEGACY_VERSION,
    ] {
        let mut fake = vec![version];
        fake.extend_from_slice(&[0u8; 40]);
        let s = base64::engine::general_purpose::STANDARD.encode(&fake);
        assert!(
            matches!(
                e.decrypt(&s),
                Err(Error::WrongFormat { found, expected })
                    if found == version && expected == VERSION
            ),
            "0x{version:02x} 应当被报为 WrongFormat"
        );
    }
}

#[test]
fn decrypt_or_original_passes_through_plaintext() {
    let e = enc(K1);
    assert_eq!(e.decrypt_or_original("plain text"), "plain text");
    let c = e.seal("real").unwrap();
    assert_eq!(e.decrypt_or_original(&c), "real");
}

/// 非字符串值渲染**值**而不是类型名 —— 曾经的 `Int(42)` → `"int"` 是静默损坏。
#[test]
fn decrypt_or_original_renders_values_not_type_names() {
    let e = enc(K1);
    assert_eq!(
        e.decrypt_or_original(&e.seal(Value::Int(42)).unwrap()),
        "42"
    );
    assert_eq!(
        e.decrypt_or_original(&e.seal(Value::Bool(true)).unwrap()),
        "true"
    );
    assert_eq!(e.decrypt_or_original(&e.seal(Value::Null).unwrap()), "");
}

#[test]
fn construction_rejects_bad_config() {
    // 缺密钥
    assert!(matches!(
        AeadEncrypter::new(&ArrayConfig::default()),
        Err(Error::MissingKey)
    ));
    // 非 AEAD 密码
    assert!(matches!(
        AeadEncrypter::new(&ArrayConfig::new(K1).with_cipher("aes-256-ecb")),
        Err(Error::CipherNotUsable { .. })
    ));
    // 长度不对
    assert!(matches!(
        AeadEncrypter::new(&ArrayConfig::new(K16)),
        Err(Error::KeyLength {
            expected: 32,
            actual: 16,
            ..
        })
    ));
    // 陌生密码
    assert!(matches!(
        AeadEncrypter::new(&ArrayConfig::new(K1).with_cipher("rc4")),
        Err(Error::UnsupportedCipher(_))
    ));
    // 空密码
    assert!(matches!(
        AeadEncrypter::new(&ArrayConfig::new(K1).with_cipher("")),
        Err(Error::MissingCipher)
    ));
}

#[test]
fn aes_128_gcm_works_with_a_16_byte_key() {
    let e = AeadEncrypter::new(&ArrayConfig::new(K16).with_cipher("aes-128-gcm")).unwrap();
    assert_eq!(e.cipher_name(), "aes-128-gcm");
    let c = e.seal("x").unwrap();
    assert_eq!(e.decrypt_text(&c).unwrap(), "x");
}

#[test]
fn ring_dedupes_the_primary_key() {
    let e =
        AeadEncrypter::new(&ArrayConfig::new(K1).with_previous_keys(vec![K1.into(), K2.into()]))
            .unwrap();
    assert_eq!(e.ring_len(), 2, "主密钥重复出现不该占两个位置");
}

#[test]
fn garbage_never_panics() {
    let e = enc(K1);
    for bad in ["", "!!!!", "AAAA", "====", &"A".repeat(1000)] {
        let _ = e.decrypt(bad);
    }
}

// ── 密钥分离（HKDF）与上下文绑定 ──────────────────────────────────────────

/// 1.2.x 的旧格式（0x01，主密钥直用）必须照旧解得开 —— 双读的回归锚。
#[test]
fn legacy_0x01_payloads_still_decrypt() {
    let e = enc(K1);
    let s = legacy_payload(K1, "存量行");

    assert!(e.is_encrypted(&s), "旧格式应当被形状判定认下");
    assert_eq!(e.decrypt_text(&s).unwrap(), "存量行");

    // 轮换把它搬成当前格式
    let moved = e.rotate_to_current_key(&s).unwrap();
    let moved_raw = base64::engine::general_purpose::STANDARD
        .decode(&moved)
        .unwrap();
    assert_eq!(moved_raw[0], VERSION, "轮换后应当是新格式");
    assert_eq!(e.decrypt_text(&moved).unwrap(), "存量行");
}

/// 环上的退役密钥也要能解旧格式：当年用旧密钥写的数据，今天在环上仍读得出。
#[test]
fn legacy_payloads_are_readable_by_the_ring() {
    let s = legacy_payload(K1, "更早的行");
    let rotated =
        AeadEncrypter::new(&ArrayConfig::new(K2).with_previous_keys(vec![K1.into()])).unwrap();
    assert_eq!(rotated.decrypt_text(&s).unwrap(), "更早的行");
}

/// 当前格式必须用 HKDF 子密钥加密 —— 主密钥原样解不开。
/// 这条是密钥分离的核心断言：DB 侧的 ECB 预言机再也够不着 GCM 的密钥。
#[test]
fn current_format_uses_the_derived_subkey() {
    let e = enc(K1);
    let raw = base64::engine::general_purpose::STANDARD
        .decode(e.seal("x").unwrap())
        .unwrap();
    assert_eq!(raw[0], VERSION);
    let nonce = &raw[1..1 + NONCE_LEN];
    let ct = &raw[1 + NONCE_LEN..];

    let master = Key::parse(K1, Cipher::Aes256Gcm).unwrap();
    let as_master = Aes256Gcm::new_from_slice(master.as_bytes()).unwrap();
    assert!(
        as_master
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &[VERSION],
                },
            )
            .is_err(),
        "新格式不该是主密钥直接加密的（否则 DB 侧 ECB 预言机又能击穿 GCM）"
    );

    let sub = subkeys::derive(&master, subkeys::AEAD_INFO, Cipher::Aes256Gcm).unwrap();
    let as_sub = Aes256Gcm::new_from_slice(sub.as_bytes()).unwrap();
    let plain = as_sub
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &[VERSION],
            },
        )
        .unwrap();
    assert_eq!(Value::String("x".into()).encode(), plain);
}

/// 上下文绑定：绑了就得对得上；对不上（换上下文、或压根不带）一律解不开。
#[test]
fn context_binding_round_trips_and_pins() {
    let e = enc(K1);
    let sealed = e
        .seal_with_context("users/42.phone", "13800138000")
        .unwrap();
    assert_eq!(
        e.decrypt_text_with_context("users/42.phone", &sealed)
            .unwrap(),
        "13800138000"
    );

    // 换个上下文（哪怕只换行号）解不开
    assert!(e.decrypt_with_context("users/43.phone", &sealed).is_err());
    // 不带上下文也解不开（AAD 不同）—— 这是特性，不是缺陷
    assert!(e.decrypt(&sealed).is_err());

    // 空上下文与非绑定格式完全等价
    let plain = e.seal("x").unwrap();
    assert_eq!(
        e.decrypt_with_context("", &plain).unwrap(),
        Value::String("x".into())
    );
}

/// 旧格式载荷没有上下文可言，带上下文的解密要明确拒绝并说清去路。
#[test]
fn legacy_payloads_have_no_context() {
    let e = enc(K1);
    let s = legacy_payload(K1, "x");
    let err = e.decrypt_with_context("any", &s).unwrap_err();
    assert!(
        err.to_string().contains("decrypt()"),
        "报错该指路，实际：{err}"
    );
}

/// 轮换的上下文变体：搬完仍绑定原上下文。
#[test]
fn rotate_with_context_stays_bound() {
    let e = enc(K1);
    let sealed = e.seal_with_context("t.col", "v").unwrap();
    let moved = e
        .rotate_to_current_key_with_context("t.col", &sealed)
        .unwrap();
    assert_ne!(moved, sealed, "nonce 随机，密文应当变了");
    assert_eq!(e.decrypt_text_with_context("t.col", &moved).unwrap(), "v");
    assert!(
        e.decrypt(&moved).is_err(),
        "绑定过的密文不该被无上下文路径解开"
    );
}

/// 上下文进 AAD ⇒ 改一个密文字节，认证同样失败。
#[test]
fn context_payloads_detect_tampering() {
    let e = enc(K1);
    let sealed = e.seal_with_context("t.col", "v").unwrap();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(&sealed)
        .unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    let tampered = base64::engine::general_purpose::STANDARD.encode(&raw);
    assert!(e.decrypt_with_context("t.col", &tampered).is_err());
}
