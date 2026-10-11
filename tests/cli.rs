// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! CLI 端到端：子进程级契约测试。
//!
//! README 把 8 个命令与退出码 0/1/2 当对外契约宣传，这里把那套契约钉住。
//! 密钥一律经环境变量注入（CLI 刻意不从 argv 读密钥），值经 stdin 管道传 ——
//! 与文档推荐的安全姿势一致。

use std::io::Write as _;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_encryptable");
const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const OTHER_HEX: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// 跑一次二进制：返回 (退出码, stdout 去尾部空白, stderr)。
fn run(args: &[&str], envs: &[(&str, &str)], stdin: Option<&str>) -> (i32, String, String) {
    let mut cmd = Command::new(BIN);
    cmd.args(args);

    // 隔离：先清掉四个可能从外部环境渗进来的变量，再注入本用例要的
    for k in [
        "ENCRYPTION_KEY",
        "ENCRYPTION_CIPHER",
        "ENCRYPTION_PREVIOUS_KEYS",
        "ENCRYPTION_DB_DRIVER",
    ] {
        if !envs.iter().any(|(n, _)| *n == k) {
            cmd.env_remove(k);
        }
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }

    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("无法启动 encryptable 二进制");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin 是 piped")
            .write_all(input.as_bytes())
            .expect("写 stdin 失败");
    }
    let out = child.wait_with_output().expect("等待子进程失败");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim_end().to_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// keygen 的输出必须能直接拿去用：抓出 export 行 → 加密 → 解密 → 还原原文。
#[test]
fn keygen_encrypt_decrypt_round_trip() {
    let (code, stdout, _) = run(&["keygen"], &[], None);
    assert_eq!(code, 0, "keygen 该成功");
    let key = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("export ENCRYPTION_KEY="))
        .expect("keygen 没打出 export 行")
        .to_owned();
    assert_eq!(key.len(), 64, "默认应为 64 字符 hex 的 32 字节密钥");

    let (code, cipher, _) = run(
        &["encrypt"],
        &[("ENCRYPTION_KEY", &key)],
        Some("13800138000"),
    );
    assert_eq!(code, 0, "encrypt 该成功");
    assert!(!cipher.contains("13800138000"), "密文不该含明文");
    assert!(!cipher.contains(&key), "密文不该含密钥");

    let (code, plain, _) = run(&["decrypt"], &[("ENCRYPTION_KEY", &key)], Some(&cipher));
    assert_eq!(code, 0, "decrypt 该成功");
    assert_eq!(plain, "13800138000");
}

/// 退出码契约：0 成功 · 1 用法错误 · 2 配置或密码学错误。
#[test]
fn exit_codes_are_contractual() {
    // 无参数 → 1，说明走 **stderr**（stdout 留给正常输出，别污染管道）
    let (code, stdout, stderr) = run(&[], &[], None);
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "用法说明不该进 stdout：{stdout:?}");
    assert!(stderr.contains("用法"), "stderr 该有用法说明");

    // --help → 0，走 stdout
    let (code, stdout, _) = run(&["--help"], &[], None);
    assert_eq!(code, 0);
    assert!(stdout.contains("用法"));

    // 缺 ENCRYPTION_KEY 的 encrypt → 1（用法错误，附可操作提示）
    let (code, _, stderr) = run(&["encrypt"], &[], Some("x"));
    assert_eq!(code, 1);
    assert!(stderr.contains("ENCRYPTION_KEY"), "{stderr}");

    // 默认 GCM 密码下跑 db-encrypt → 1，且提示改用 aes-256-ecb
    let (code, _, stderr) = run(&["db-encrypt"], &[("ENCRYPTION_KEY", KEY_HEX)], Some("x"));
    assert_eq!(code, 1);
    assert!(stderr.contains("aes-256-ecb"), "{stderr}");

    // 坏密钥解合法密文 → 2（配置/密码学错误）
    let (_, cipher, _) = run(&["encrypt"], &[("ENCRYPTION_KEY", KEY_HEX)], Some("secret"));
    let (code, _, _) = run(
        &["decrypt"],
        &[("ENCRYPTION_KEY", OTHER_HEX)],
        Some(&cipher),
    );
    assert_eq!(code, 2);
}

/// 管道输入的尾随空白要整段去掉 —— `echo` 会附赠 `\n`，Windows 管道还有 `\r`，
/// 残留会让解密静默失败（曾经只 trim `\n`）。
#[test]
fn stdin_pipe_is_read_and_trimmed() {
    let (_, cipher, _) = run(
        &["encrypt"],
        &[("ENCRYPTION_KEY", KEY_HEX)],
        Some("13800138000"),
    );

    for piped in [format!("{cipher}\n"), format!("{cipher}\r\n")] {
        let (code, plain, _) = run(&["decrypt"], &[("ENCRYPTION_KEY", KEY_HEX)], Some(&piped));
        assert_eq!(code, 0, "{piped:?} 该能解开");
        assert_eq!(plain, "13800138000");
    }
}

/// `--driver` 严格校验：打错字报用法错误（别静默按 MySQL），且只服务 sql 命令。
#[test]
fn driver_flag_is_strict_and_sql_only() {
    let envs = [
        ("ENCRYPTION_KEY", KEY_HEX),
        ("ENCRYPTION_CIPHER", "aes-256-ecb"),
    ];

    let (code, _, stderr) = run(&["sql", "phone", "--driver", "oracle"], &envs, None);
    assert_eq!(code, 1, "未知方言该报用法错误");
    assert!(stderr.contains("oracle"), "{stderr}");

    let (code, _, _) = run(&["encrypt", "--driver", "mysql"], &envs, Some("x"));
    assert_eq!(code, 1, "--driver 对非 sql 命令该被拒");
}

/// db-encrypt ↔ db-decrypt 往返，且确定性（同一明文两次同密文）。
#[test]
fn db_commands_round_trip_deterministically() {
    let envs = [
        ("ENCRYPTION_KEY", KEY_HEX),
        ("ENCRYPTION_CIPHER", "aes-256-ecb"),
    ];

    let (code, a, _) = run(&["db-encrypt"], &envs, Some("13800138000"));
    assert_eq!(code, 0);
    let (_, b, _) = run(&["db-encrypt"], &envs, Some("13800138000"));
    assert_eq!(a, b, "DB 侧必须确定性 —— 否则等值查询匹配不上");

    let (code, plain, _) = run(&["db-decrypt"], &envs, Some(&a));
    assert_eq!(code, 0);
    assert_eq!(plain, "13800138000");
}

/// `sql` 命令的片段形状与告警：密钥进 SQL 的提醒走 stderr，片段本身走 stdout。
#[test]
fn sql_command_warns_on_stderr_and_prints_fragment_on_stdout() {
    let envs = [
        ("ENCRYPTION_KEY", KEY_HEX),
        ("ENCRYPTION_CIPHER", "aes-256-ecb"),
    ];

    let (code, stdout, stderr) = run(&["sql", "phone", "--driver", "pgsql"], &envs, None);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("CASE "), "片段该在 stdout：{stdout}");
    assert!(stdout.contains("convert_from"), "pgsql 方言不对：{stdout}");
    assert!(
        stderr.contains("慢查询日志"),
        "该提醒密钥进 SQL 的去向：{stderr}"
    );
}
