// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 本模块的单元测试。

use super::*;
use crate::config::ArrayConfig;

const K1: &str = "0123456789abcdef0123456789abcdef";
const K2: &str = "fedcba9876543210fedcba9876543210";
const K16: &str = "0123456789abcdef";

fn enc(key: &str) -> AeadEncrypter {
    AeadEncrypter::new(&ArrayConfig::new(key)).unwrap()
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

/// PHP 版的坑：一段 base64 解出来首字节恰好是 0x01 的**明文**会被误判成密文
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
    let mut fake = vec![crate::encrypter::DbEncrypter::VERSION];
    fake.extend_from_slice(&[0u8; 40]);
    let s = base64::engine::general_purpose::STANDARD.encode(&fake);
    assert!(matches!(
        e.decrypt(&s),
        Err(Error::WrongFormat {
            found: 0x02,
            expected: 0x01
        })
    ));
}

#[test]
fn decrypt_or_original_passes_through_plaintext() {
    let e = enc(K1);
    assert_eq!(e.decrypt_or_original("plain text"), "plain text");
    let c = e.seal("real").unwrap();
    assert_eq!(e.decrypt_or_original(&c), "real");
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
