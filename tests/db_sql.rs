// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! DB 侧：确定性、SQL 片段形状、以及标识符注入防护。
//!
//! 这个文件里的断言刻意写成**逐字符**比对片段全文。片段是本 crate 交给数据库的
//! 唯一产物，少一个括号、多一个引号都不会在 Rust 这边报错，只会在生产库上变成
//! 一个语法错误或更糟的东西。所以让它在单元测试里就红。

use base64::Engine as _;
use encryptable::config::{ArrayConfig, DbDriver};
use encryptable::{DbEncrypter, Error};

/// 与 src/encrypter/db.rs 的金标量同一把密钥。
const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn enc(driver: DbDriver) -> DbEncrypter {
    DbEncrypter::new(
        &ArrayConfig::new(KEY)
            .with_cipher("aes-256-ecb")
            .with_db_driver(driver),
    )
    .unwrap()
}

/// 片段全文逐字符钉死 —— 两种方言各一条。
#[test]
fn fragment_text_is_pinned() {
    let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    assert_eq!(
        enc(DbDriver::Mysql)
            .decrypt_expr("phone", DbDriver::Mysql)
            .unwrap(),
        format!(
            "CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64(phone), 2 ), UNHEX('{hex}') ) USING 'UTF8' )"
        )
    );

    assert_eq!(
        enc(DbDriver::Postgres)
            .decrypt_expr("phone", DbDriver::Postgres)
            .unwrap(),
        format!(
            "convert_from( decrypt( substring( decode(phone, 'base64') from 2 ), '\\x{hex}'::bytea, 'aes-ecb' ), 'UTF8' )"
        )
    );
}

/// 片段里不得出现密钥的**原始字节**，只允许出现它的 hex 编码。
///
/// 这里必须用一把**不是 hex 形状**的密钥：本文件顶部的 `KEY` 是 64 个十六进制
/// 字符，它本身就是自己的 hex 表示，拿它做这条断言永远是假阳性。
#[test]
fn fragment_never_contains_the_raw_key() {
    const RAW: &str = "0123456789abcdefghijklmnopqrstuv";
    assert_eq!(RAW.len(), 32);

    let e = DbEncrypter::new(&ArrayConfig::new(RAW).with_cipher("aes-256-ecb")).unwrap();

    for driver in [DbDriver::Mysql, DbDriver::Postgres] {
        let sql = e.decrypt_expr("phone", driver).unwrap();
        assert!(!sql.contains(RAW), "{driver:?} 片段含密钥明文: {sql}");
        // 但它的 hex 形式必须在（数据库要靠它解密）
        let hex = e.key_hex();
        assert!(sql.contains(hex.as_str()), "{driver:?} 片段里没有密钥");
    }
}

/// 标识符白名单：放行合法列名。
#[test]
fn legal_column_names_are_accepted() {
    let e = enc(DbDriver::Mysql);
    for ok in [
        "phone",
        "_internal",
        "users.phone",
        "public.users.phone",
        "A9",
        "c1",
    ] {
        assert!(
            e.decrypt_expr(ok, DbDriver::Mysql).is_ok(),
            "{ok:?} 应当被接受"
        );
    }
}

/// 注入形状必须被拒 —— 这是这条路径上唯一的攻击面。
#[test]
fn injection_shapes_are_rejected() {
    let e = enc(DbDriver::Mysql);
    for bad in [
        "",
        "phone; DROP TABLE users",
        "phone) OR 1=1 --",
        "phone'",
        "\"phone\"",
        "phone p",
        "1phone",
        ".phone",
        "phone.",
        "a..b",
        "phone\n",
        "phone\t",
        "phone/*x*/",
        "phone)`",
        "表名",
        "phone--",
        "phone#",
        "phone%",
    ] {
        let got = e.decrypt_expr(bad, DbDriver::Mysql);
        assert!(
            matches!(got, Err(Error::InvalidColumnRef(_))),
            "{bad:?} 应当被拒绝，实际 {got:?}"
        );
    }
}

/// 超长标识符要拒 —— MySQL 的标识符上限是 64，这里按 63 收。
#[test]
fn overlong_identifiers_are_rejected() {
    let e = enc(DbDriver::Mysql);
    assert!(e.decrypt_expr(&"a".repeat(63), DbDriver::Mysql).is_ok());
    assert!(e.decrypt_expr(&"a".repeat(64), DbDriver::Mysql).is_err());
}

/// 引号只包住固定常量与纯 hex —— 十六进制字符集里没有引号，
/// 所以密钥不可能从字面量里逃出去。这是不再需要 SQL 转义的原因。
#[test]
fn quotes_only_wrap_constants_and_hex() {
    let e = enc(DbDriver::Mysql);
    let hex = e.key_hex();
    let hex = hex.as_str();

    for driver in [DbDriver::Mysql, DbDriver::Postgres] {
        let sql = e.decrypt_expr("phone", driver).unwrap();
        assert!(
            sql.matches('\'').count().is_multiple_of(2),
            "引号不成对: {sql}"
        );

        for quoted in sql.split('\'').skip(1).step_by(2) {
            let bare = quoted.strip_prefix("\\x").unwrap_or(quoted);
            let ok = matches!(bare, "UTF8" | "base64" | "aes-ecb") || bare == hex;
            assert!(ok, "{driver:?} 里有意料之外的引号内容: {quoted:?}");
        }
    }
}

/// 确定性：同明文同密文，且与密钥 hex 无关（hex 只是另一种表示）。
#[test]
fn db_payloads_are_deterministic_across_instances() {
    let a = enc(DbDriver::Mysql);
    let b = enc(DbDriver::Postgres); // 方言不影响密文本身
    assert_eq!(
        a.encrypt("13800138000").unwrap(),
        b.encrypt("13800138000").unwrap()
    );
    assert_eq!(
        a.encrypt("13800138000").unwrap(),
        a.encrypt("13800138000").unwrap()
    );
}

/// 版本字节必须真的写在第一个字节上，否则 SQL 的 `SUBSTRING(..., 2)` 会错位。
#[test]
fn version_byte_is_the_first_byte() {
    let e = enc(DbDriver::Mysql);
    for plain in ["", "a", "0123456789abcdef", "很长的一段中文内容用于测试"] {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(e.encrypt(plain).unwrap())
            .unwrap();
        assert_eq!(raw[0], 0x02, "明文 {plain:?} 的版本字节不对");
        assert_eq!((raw.len() - 1) % 16, 0, "去掉版本字节后应当正好是整块");
    }
}

/// 等值查询的核心前提：明文差一个字节，密文就必须完全不同（至少不同块）。
#[test]
fn near_identical_plaintexts_produce_different_payloads() {
    let e = enc(DbDriver::Mysql);
    assert_ne!(
        e.encrypt("13800138000").unwrap(),
        e.encrypt("13800138001").unwrap()
    );
    assert_ne!(e.encrypt("a").unwrap(), e.encrypt("b").unwrap());
}

/// 绑定查询的用法：算出密文 → 绑进 WHERE。
///
/// 这里模拟的是「同一列、同一密钥，两次独立调用得到同一个值」——
/// 索引匹配得上的前提。
#[test]
fn binding_recipe_yields_a_stable_value() {
    let e = enc(DbDriver::Mysql);
    let stored = e.encrypt("13800138000").unwrap(); // 写库时
    let probe = e.encrypt("13800138000").unwrap(); // 查询时
    assert_eq!(stored, probe, "两次算出的密文不同，等值查询会永远匹配不上");

    let miss = e.encrypt("13800138001").unwrap();
    assert_ne!(stored, miss);
}

/// 非确定性密码配到 DB 侧必须当场报错 —— 静默失效最难查。
#[test]
fn non_deterministic_ciphers_are_refused() {
    for cipher in ["aes-256-gcm", "aes-128-gcm", "aes-256-cbc", "aes-128-cbc"] {
        let got = DbEncrypter::new(&ArrayConfig::new(KEY).with_cipher(cipher));
        assert!(
            matches!(got, Err(Error::CipherNotUsable { .. })),
            "{cipher} 不该被 DB 侧接受，实际 {got:?}"
        );
    }
}

/// 16 字节密钥配 aes-128-ecb 也能用。
#[test]
fn aes_128_ecb_is_supported() {
    let e =
        DbEncrypter::new(&ArrayConfig::new("0123456789abcdef").with_cipher("aes-128-ecb")).unwrap();
    assert_eq!(e.cipher_name(), "aes-128-ecb");
    assert_eq!(e.key_hex().len(), 32);
    assert_eq!(e.decrypt(&e.encrypt("hi").unwrap()).unwrap(), "hi");
}

/// 需要真实数据库才能验的两件事：片段能否执行、以及我们的 ECB 字节
/// MySQL/pgcrypto 是否认得。
///
/// 默认不跑 —— CI 里没有数据库。要验的时候：
///
/// ```text
/// ENCRYPTION_TEST_MYSQL=mysql://... cargo test --test db_sql -- --ignored
/// ```
#[test]
#[ignore = "需要真实数据库，默认跳过"]
fn live_database_can_decrypt_our_fragments() {
    // 占位：接上驱动后，执行
    //   SELECT <decrypt_expr('col', driver)> FROM t
    // 并断言结果等于明文。
    //
    // 这是唯一能真正证明「数据库读得懂我们写的字节」的测试，因此值得留着 ——
    // 金标量只证明了我们与 OpenSSL 一致，而 MySQL 的 AES_DECRYPT 是另一套实现。
    eprintln!("需要真实 MySQL / PostgreSQL 才能运行；见本测试上方的说明。");
}
