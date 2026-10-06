// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 端到端走一遍两条路径，并演示一次密钥轮换。
//!
//! 跑起来看：
//!
//! ```text
//! cargo run --example quickstart
//! ```

use encryptable::config::{ArrayConfig, DbDriver};
use encryptable::{AeadEncrypter, DbEncrypter, Error};

/// 演示里用的密钥。生产环境请用 `encryptable keygen` 生成，别硬编码。
const OLD_KEY: &str = "old-old-old-old-old-old-old-old-";
const NEW_KEY: &str = "new-new-new-new-new-new-new-new-";

/// 一把只用于 DB 侧的确定性密钥。
const DB_KEY: &str = "0123456789abcdef0123456789abcdef";

fn main() -> Result<(), Error> {
    println!("{}", encryptable::pet::ASCII);
    println!();

    app_side()?;
    db_side()?;
    rotation()?;

    Ok(())
}

/// 应用侧：默认路径。随机 nonce，带认证。
fn app_side() -> Result<(), Error> {
    println!("── 应用侧：AES-256-GCM（默认选它）──");

    let encrypter = AeadEncrypter::new(&ArrayConfig::new(OLD_KEY))?;
    println!(
        "密码：{}，环上 {} 把钥匙",
        encrypter.cipher_name(),
        encrypter.ring_len()
    );

    let phone = "13800138000";
    let ciphertext = encrypter.encrypt(phone)?;
    println!("明文   {phone}");
    println!("密文   {ciphertext}");
    println!("解回   {}", encrypter.decrypt_text(&ciphertext)?);

    // 同一个明文两次加密结果不同 —— nonce 是随机的
    let again = encrypter.seal(phone)?;
    println!(
        "再加密一次 {}",
        if again == ciphertext {
            "相同（不该发生）"
        } else {
            "不同（nonce 随机，符合预期）"
        }
    );

    // 类型是带在信封里的
    let n = encrypter.encrypt(42i64)?;
    println!("整数 42 解回来是 {:?}", encrypter.decrypt(&n)?);

    println!();
    Ok(())
}

/// DB 侧：确定性 ECB，可以绑进 WHERE。
fn db_side() -> Result<(), Error> {
    println!("── DB 侧：AES-256-ECB（确定性，可按原值查询）──");

    let db = DbEncrypter::new(
        &ArrayConfig::new(DB_KEY)
            .with_cipher("aes-256-ecb")
            .with_db_driver(DbDriver::Postgres),
    )?;

    let phone = "13800138000";

    // ① 写入时算一次
    let stored = db.encrypt(phone)?;
    // ② 查询时再算一次，必须一模一样，否则等值查询永远匹配不上
    let probe = db.encrypt(phone)?;
    println!("写库密文 {stored}");
    println!("查询密文 {probe}");
    println!(
        "一致吗   {}",
        if stored == probe {
            "一致 —— 索引匹配得上"
        } else {
            "不一致（不该发生）"
        }
    );

    // ③ 需要明文时让数据库自己解（注意：这条表达式含主密钥，别写进日志）
    println!(
        "\n让数据库解密的表达式（PostgreSQL 方言）：\n  {}\n",
        db.decrypt_expr("phone", DbDriver::Postgres)?
    );

    println!("提醒：过滤条件优先用 `db.encrypt(输入)` 的结果做参数绑定，");
    println!("      那样既不用把密钥写进 SQL，也能吃上该列上的索引。");

    println!();
    Ok(())
}

/// 轮换：换主密钥而存量数据照读。
fn rotation() -> Result<(), Error> {
    println!("── 密钥轮换：零停机换主密钥 ──");

    // 换之前写进去的数据
    let before = AeadEncrypter::new(&ArrayConfig::new(OLD_KEY))?;
    let rows: Vec<String> = ["13800138000", "张三", "北京市朝阳区"]
        .iter()
        .map(|s| before.seal(*s))
        .collect::<Result<_, _>>()?;
    println!("用旧密钥写了 {} 行", rows.len());

    // 第一步：新主密钥上任，旧的退进 previous_keys
    let after =
        AeadEncrypter::new(&ArrayConfig::new(NEW_KEY).with_previous_keys(vec![OLD_KEY.into()]))?;
    println!(
        "轮换后环上 {} 把钥匙，存量照读：{}",
        after.ring_len(),
        after.decrypt_text(&rows[0])?
    );

    // 第二步：后台任务把存量逐个搬到新主密钥下
    let moved: Vec<String> = rows
        .iter()
        .map(|r| after.rotate_to_current_key(r))
        .collect::<Result<_, _>>()?;

    // 搬到之后，只留新密钥也能读；旧密钥已经读不了搬过的行
    let only_new = AeadEncrypter::new(&ArrayConfig::new(NEW_KEY))?;
    println!(
        "搬完后只用新密钥解开第一行：{}",
        only_new.decrypt_text(&moved[0])?
    );
    println!(
        "旧密钥还能读搬过的行吗：{}",
        match before.decrypt(&moved[0]) {
            Ok(_) => "能（不该发生）",
            Err(_) => "不能 —— 可以安全退役它了",
        }
    );

    println!();
    Ok(())
}
