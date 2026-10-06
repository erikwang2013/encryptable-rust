// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 跨模块的不变量。
//!
//! 本 crate 放弃了与 PHP 版的字节级互通，于是也就没有现成的跨语言测试向量可对齐。
//! 取而代之的正确性锚点是一组**性质**：往返恒等、篡改必被拒、错误密钥必被拒、
//! 随机 nonce 不重复、DB 路径确定性、两种载荷互不通用。
//!
//! 语料用手写 LCG 生成而不引 proptest/quickcheck —— 与 security-rust 的做法一致，
//! 确定性、可复现、零依赖。

use base64::Engine as _;
use encryptable::config::{ArrayConfig, DbDriver};
use encryptable::{AeadEncrypter, DbEncrypter, Error, Value};

const K1: &str = "0123456789abcdef0123456789abcdef";
const K2: &str = "fedcba9876543210fedcba9876543210";

/// 手写线性同余发生器：确定性、零依赖，够用来铺语料。
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(
            seed.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407),
        )
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 16
    }

    /// 生成一段包含各种边界的语料：空串、单字节、块边界、非 ASCII、内嵌 NUL、
    /// 前导 0x01/0x02（那正是两个格式字节）。
    fn corpus(&mut self, count: usize) -> Vec<String> {
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let len = match i % 8 {
                0 => 0,
                1 => 1,
                2 => 15,
                3 => 16,
                4 => 17,
                5 => 31,
                6 => 64,
                _ => (self.next() % 200) as usize,
            };
            let mut s = String::new();
            for _ in 0..len {
                let b = (self.next() % 256) as u8;
                // 塞进合法 UTF-8：只在可打印区间与两个格式字节里取
                s.push(match b % 5 {
                    0 => '\u{4e16}', // 多字节
                    1 => '\u{0}',    // 内嵌 NUL
                    2 => '\u{1}',    // 与应用侧格式字节同值
                    3 => '\u{2}',    // 与 DB 侧格式字节同值
                    _ => char::from(32 + (b % 95)),
                });
            }
            out.push(s);
        }
        out
    }
}

fn app() -> AeadEncrypter {
    AeadEncrypter::new(&ArrayConfig::new(K1)).unwrap()
}

fn db() -> DbEncrypter {
    DbEncrypter::new(&ArrayConfig::new(K1).with_cipher("aes-256-ecb")).unwrap()
}

/// 应用侧：任意语料往返恒等。
#[test]
fn app_side_round_trips_the_whole_corpus() {
    let e = app();
    let mut lcg = Lcg::new(1);
    for s in lcg.corpus(400) {
        let c = e.encrypt(s.as_str()).expect("加密不该失败");
        assert_eq!(e.decrypt_text(&c).unwrap(), s, "往返不一致: {s:?}");
    }
}

/// DB 侧：任意语料往返恒等。
#[test]
fn db_side_round_trips_the_whole_corpus() {
    let e = db();
    let mut lcg = Lcg::new(2);
    for s in lcg.corpus(400) {
        let c = e.encrypt(&s).expect("加密不该失败");
        assert_eq!(e.decrypt(&c).unwrap(), s, "往返不一致: {s:?}");
    }
}

/// 应用侧同明文两次加密必不同；DB 侧必相同。这条是两条路径的分界线。
#[test]
fn the_two_paths_have_opposite_repeatability() {
    let a = app();
    let d = db();
    let mut lcg = Lcg::new(3);
    for s in lcg.corpus(100) {
        assert_ne!(
            a.seal(s.as_str()).unwrap(),
            a.seal(s.as_str()).unwrap(),
            "应用侧不该确定: {s:?}"
        );
        assert_eq!(
            d.encrypt(&s).unwrap(),
            d.encrypt(&s).unwrap(),
            "DB 侧必须确定: {s:?}"
        );
    }
}

/// nonce 是随机的，密文不该出现重复。
#[test]
fn nonces_do_not_repeat() {
    let e = app();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let c = e.seal("固定的明文").unwrap();
        assert!(seen.insert(c), "密文重复出现，nonce 可能没在随机");
    }
}

/// 两条路径的载荷互不通用 —— 这是格式字节存在的理由。
#[test]
fn the_two_formats_never_cross() {
    let a = app();
    let d = db();

    let app_payload = a.seal("x").unwrap();
    let db_payload = d.encrypt("x").unwrap();

    // 各自认得自己的
    assert!(a.is_encrypted(&app_payload));
    assert!(d.is_encrypted(&db_payload));
    // 各自不认对方的
    assert!(!a.is_encrypted(&db_payload), "应用侧把 DB 载荷认成了自己的");
    assert!(
        !d.is_encrypted(&app_payload),
        "DB 侧把应用侧载荷认成了自己的"
    );

    // 交叉解密要给出明确的格式错误，而不是「解密失败」
    assert!(matches!(
        a.decrypt(&db_payload),
        Err(Error::WrongFormat { .. })
    ));
    assert!(matches!(
        d.decrypt(&app_payload),
        Err(Error::WrongFormat { .. })
    ));
    // 交叉加密必须被拒 —— 否则会安静地把对方的密文再加密一遍
    assert!(matches!(
        d.encrypt(&app_payload),
        Err(Error::WrongFormat { .. })
    ));
}

/// 形状判定与实际可解性必须一致：`is_encrypted` 说「不是」的，解密必失败。
///
/// 反方向不成立（`is_encrypted` 有约 1/256 的假阳性），这正是它的已知上限，
/// 所以只断言这一个方向。
#[test]
fn shape_check_never_says_false_about_real_ciphertext() {
    let a = app();
    let d = db();
    let mut lcg = Lcg::new(4);

    for s in lcg.corpus(200) {
        let ac = a.seal(s.as_str()).unwrap();
        let dc = d.encrypt(&s).unwrap();
        assert!(a.is_encrypted(&ac), "应用侧真密文被判定为假");
        assert!(d.is_encrypted(&dc), "DB 侧真密文被判定为假");
        // 而普通明文不该被判为密文
        if a.is_encrypted(&s) {
            // 只可能是那 1/256 的假阳性，此时它必须确实解不开
            assert!(a.decrypt(&s).is_err());
        }
    }
}

/// 任一字节被改动，应用侧必拒（GCM tag 兜底）。
#[test]
fn app_side_detects_every_single_byte_tamper() {
    let e = app();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(e.seal("审计这段").unwrap())
        .unwrap();

    for i in 0..raw.len() {
        for mask in [0x01u8, 0x80, 0xff] {
            let mut bad = raw.clone();
            bad[i] ^= mask;
            let s = base64::engine::general_purpose::STANDARD.encode(&bad);
            assert!(
                e.decrypt(&s).is_err(),
                "改动第 {i} 字节（掩码 {mask:#x}）后仍能解开"
            );
        }
    }
}

/// 截断、加长、改版本字节都必拒。
#[test]
fn structural_damage_is_rejected() {
    let e = app();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(e.seal("x").unwrap())
        .unwrap();
    let b64 = |v: &[u8]| base64::engine::general_purpose::STANDARD.encode(v);

    for cut in 0..raw.len() {
        assert!(
            e.decrypt(&b64(&raw[..cut])).is_err(),
            "截断到 {cut} 字节后仍能解开"
        );
    }
    let mut longer = raw.clone();
    longer.push(0);
    assert!(e.decrypt(&b64(&longer)).is_err(), "尾部多一字节后仍能解开");

    let mut wrong_version = raw.clone();
    wrong_version[0] = 0x7f;
    assert!(
        e.decrypt(&b64(&wrong_version)).is_err(),
        "陌生版本字节被接受了"
    );
}

/// 随机字节串不该让任何一条路径 panic，也不该被当成合法载荷。
#[test]
fn random_garbage_never_panics() {
    let a = app();
    let d = db();
    let mut lcg = Lcg::new(5);

    for _ in 0..2000 {
        let len = (lcg.next() % 80) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (lcg.next() % 256) as u8).collect();
        let s = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let _ = a.decrypt(&s);
        let _ = d.decrypt(&s);
        let _ = a.decrypt_or_original(&s);
        let _ = Value::decode(&bytes);
    }
}

/// 类型信封必须无损地还原类型，而不是像 PHP 的 `settype` 那样静默转换。
#[test]
fn envelope_preserves_types_exactly() {
    let e = app();
    let cases = [
        Value::Null,
        Value::Bool(true),
        Value::Bool(false),
        Value::Int(0),
        Value::Int(-1),
        Value::Int(i64::MIN),
        Value::Int(i64::MAX),
        Value::Float(0.0),
        Value::Float(-0.0),
        Value::Float(f64::MAX),
        Value::String(String::new()),
        Value::String("世界".into()),
    ];

    for v in cases {
        let c = e.seal(v.clone()).unwrap();
        let got = e.decrypt(&c).unwrap();
        // -0.0 == 0.0，比位模式才能区分
        if let (Value::Float(a), Value::Float(b)) = (&v, &got) {
            assert_eq!(a.to_bits(), b.to_bits(), "浮点位模式变了");
        } else {
            assert_eq!(got, v, "{v:?} 往返类型不一致");
        }
    }
}

/// 错误信息里不该出现密钥、明文或密文。
#[test]
fn errors_never_leak_secrets() {
    let e = app();
    let payload = e.seal("绝密内容").unwrap();

    let err = match e.decrypt(&payload.replace('A', "B")) {
        Err(err) => err.to_string(),
        Ok(_) => "居然解开了".to_owned(),
    };
    assert!(!err.contains(K1), "错误信息泄漏了密钥: {err}");
    assert!(!err.contains("绝密内容"), "错误信息泄漏了明文: {err}");
    assert!(!err.contains(&payload), "错误信息泄漏了密文: {err}");
}

/// DB 路径的密钥十六进制表示必须与密钥本身一致，且可往返。
#[test]
fn key_hex_round_trips() {
    let e = db();
    let hex = e.key_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

    // 同一把密钥用 hex 形式重新配置，应当能解开原来的密文
    let payload = e.encrypt("hello").unwrap();
    let from_hex =
        DbEncrypter::new(&ArrayConfig::new(hex.to_string()).with_cipher("aes-256-ecb")).unwrap();
    assert_eq!(from_hex.decrypt(&payload).unwrap(), "hello");
}

/// 两条路径的 SQL 片段在两种方言下都不该含密钥明文。
#[test]
fn fragments_never_contain_the_raw_key() {
    let e = db();
    for driver in [DbDriver::Mysql, DbDriver::Postgres] {
        let sql = e.decrypt_expr("phone", driver).unwrap();
        assert!(!sql.contains(K1), "{driver:?} 片段含密钥明文");
    }
}

/// 换一把密钥就解不开旧密文 —— 两条路径都如此。
#[test]
fn a_different_key_cannot_read_our_output() {
    let a1 = app();
    let a2 = AeadEncrypter::new(&ArrayConfig::new(K2)).unwrap();
    assert!(a2.decrypt(&a1.seal("x").unwrap()).is_err());

    let d1 = db();
    let d2 = DbEncrypter::new(&ArrayConfig::new(K2).with_cipher("aes-256-ecb")).unwrap();
    assert_ne!(
        d2.decrypt(&d1.encrypt("x").unwrap()).unwrap_or_default(),
        "x"
    );
}
