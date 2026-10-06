// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 密钥轮换：整条零停机迁移路径。
//!
//! 场景就是数据库里躺着一堆用旧密钥写的密文，运维要换密钥而不能停机、
//! 不能一次性重写全表。

use encryptable::config::{ArrayConfig, EnvConfig};
use encryptable::{AeadEncrypter, EncryptableConfig};

const OLD: &str = "old-old-old-old-old-old-old-old-";
const NEW: &str = "new-new-new-new-new-new-new-new-";
const ANCIENT: &str = "ancient-ancient-ancient-ancient-";

fn app(key: &str, previous: &[&str]) -> AeadEncrypter {
    AeadEncrypter::new(
        &ArrayConfig::new(key)
            .with_previous_keys(previous.iter().map(|s| (*s).to_owned()).collect()),
    )
    .unwrap()
}

/// 第二步：新主密钥上任，旧的进环，存量照读。
#[test]
fn reads_survive_the_key_swap() {
    let before = app(OLD, &[]);
    let rows: Vec<String> = ["13800138000", "张三", "北京市朝阳区"]
        .iter()
        .map(|s| before.seal(*s).unwrap())
        .collect();

    let after = app(NEW, &[OLD]);

    for (row, expected) in rows.iter().zip(["13800138000", "张三", "北京市朝阳区"]) {
        assert_eq!(after.decrypt_text(row).unwrap(), expected);
    }
    assert_eq!(after.ring_len(), 2);
}

/// 第三步：后台任务把存量逐个搬到新主密钥下。
#[test]
fn rotation_moves_rows_onto_the_primary_key() {
    let before = app(OLD, &[]);
    let after = app(NEW, &[OLD]);

    let rows: Vec<String> = ["a", "bb", "ccc"]
        .iter()
        .map(|s| before.seal(*s).unwrap())
        .collect();

    let moved: Vec<String> = rows
        .iter()
        .map(|r| after.rotate_to_current_key(r).unwrap())
        .collect();

    // 搬完之后，只拿新密钥（环里没有旧的）也解得开
    let only_new = app(NEW, &[]);
    for (m, expected) in moved.iter().zip(["a", "bb", "ccc"]) {
        assert_eq!(only_new.decrypt_text(m).unwrap(), expected);
    }

    // 而旧密钥单独已经解不开搬过的行
    for m in &moved {
        assert!(before.decrypt(m).is_err(), "搬过的行还能用旧密钥解开");
    }
}

/// 多次退役的密钥都还在环上时，任意一代都能解开。
#[test]
fn the_whole_ring_is_walked() {
    let gen1 = app(ANCIENT, &[]);
    let gen2 = app(OLD, &[ANCIENT]);
    let gen3 = app(NEW, &[OLD, ANCIENT]);

    let a = gen1.seal("第一代").unwrap();
    let b = gen2.seal("第二代").unwrap();
    let c = gen3.seal("第三代").unwrap();

    for payload in [&a, &b, &c] {
        assert!(gen3.decrypt_text(payload).is_ok(), "环上应当有一把能解开");
    }
    assert_eq!(gen3.ring_len(), 3);

    // 搬到最新一代之后，只留新密钥也能全读
    let moved: Vec<String> = [a, b, c]
        .iter()
        .map(|p| gen3.rotate_to_current_key(p).unwrap())
        .collect();
    let only_gen3 = app(NEW, &[]);
    for m in &moved {
        assert!(only_gen3.decrypt_text(m).is_ok());
    }
}

/// 退役密钥顺序：最近退役的在前，且与主密钥重复的会被去掉。
#[test]
fn ring_dedupes_and_orders() {
    let e = app(NEW, &[OLD, NEW, OLD, ANCIENT]);
    assert_eq!(e.ring_len(), 3, "主密钥与重复项应当被去掉");
}

/// 轮换是个幂等操作：对已经用主密钥加密的载荷再轮换，语义不变。
#[test]
fn rotation_is_idempotent_in_effect() {
    let e = app(NEW, &[OLD]);
    let first = e.seal("数据").unwrap();
    let second = e.rotate_to_current_key(&first).unwrap();
    assert_ne!(first, second, "密文会变，因为 nonce 随机");
    assert_eq!(e.decrypt_text(&second).unwrap(), "数据");
    // 连着再来一次也还是同样的明文
    let third = e.rotate_to_current_key(&second).unwrap();
    assert_eq!(e.decrypt_text(&third).unwrap(), "数据");
}

/// 明文喂进来应当原样返回，方便批处理无脑跑。
#[test]
fn rotation_passes_plaintext_through() {
    let e = app(NEW, &[OLD]);
    assert_eq!(e.rotate_to_current_key("还不是密文").unwrap(), "还不是密文");
}

/// 空字符串与不可识别的内容都不该让轮换炸掉。
#[test]
fn rotation_survives_unusual_input() {
    let e = app(NEW, &[OLD]);
    for s in ["", "x", "不是 base64！！", "AAAA"] {
        assert_eq!(e.rotate_to_current_key(s).unwrap(), s);
    }
}

/// 环境变量那条路径也要能配出密钥环。
#[test]
fn env_config_builds_a_ring() {
    let map = std::collections::HashMap::from([
        ("ENCRYPTION_KEY".to_owned(), NEW.to_owned()),
        (
            "ENCRYPTION_PREVIOUS_KEYS".to_owned(),
            format!("{OLD}, {ANCIENT}"),
        ),
    ]);
    let config = EnvConfig::from_env_with(|k| map.get(k).cloned()).unwrap();
    assert_eq!(config.previous_keys().len(), 2);

    let e = AeadEncrypter::new(&config).unwrap();
    assert_eq!(e.ring_len(), 3);
}

/// 环上一把钥匙长度不对，构造时就该炸 —— 否则那把钥匙永远解不开，
/// 而现场表现只是「全都失败了」。
#[test]
fn a_malformed_previous_key_fails_at_construction() {
    let err = AeadEncrypter::new(&ArrayConfig::new(NEW).with_previous_keys(vec!["太短了".into()]));
    assert!(err.is_err(), "长度不对的退役密钥应当被拒绝");
}

/// 空白的退役密钥直接跳过，不该报错（配置里常见尾随逗号）。
#[test]
fn blank_previous_keys_are_skipped() {
    let e = AeadEncrypter::new(&ArrayConfig::new(NEW).with_previous_keys(vec![
        "".into(),
        "   ".into(),
        OLD.into(),
    ]))
    .unwrap();
    assert_eq!(e.ring_len(), 2);
}
