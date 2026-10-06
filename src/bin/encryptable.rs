// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! `encryptable` 命令行工具。
//!
//! 手动解析参数而不引 `clap`：命令只有八个，而 `clap` 会比本 crate 其余全部
//! 依赖加起来还重。密钥一律从**环境变量**读，不从 argv 读 —— argv 会通过
//! `ps` 和 shell 历史泄漏。

use std::io::Read as _;
use std::process::ExitCode;

use encryptable::config::{DbDriver, EncryptableConfig, EnvConfig};
use encryptable::{AeadEncrypter, DbEncrypter, Error};

/// 用法说明。
const USAGE: &str = "\
encryptable — 敏感字段的可检索加密

用法：
  encryptable <命令> [参数]

应用侧（AES-256-GCM，默认）：
  encrypt <明文>            加密一个值
  decrypt <密文>            解密一个值
  rotate  <密文>            用当前主密钥重新加密（读旧密钥、写新密钥）

DB 侧（AES-256-ECB，确定性，可被 SQL 解密）：
  db-encrypt <明文>         产出可绑定到 WHERE 的密文
  db-decrypt <密文>         还原（迁移用，不走 SQL）
  sql <列名> [--driver ...] 打印让数据库自己解密的 SQL 表达式

其它：
  keygen                    生成一把全新的 32 字节密钥
  pet                       打印项目宠物 Locky · 小锁灵

选项：
  --driver mysql|pgsql      sql 命令的方言（默认取 ENCRYPTION_DB_DRIVER）
  --raw                     不解码输入，直接当成字面参数
  --help, -h                显示本说明
  --version, -V             显示版本与项目宠物

环境变量：
  ENCRYPTION_KEY            主密钥（32 字节字面量、64 位 hex，或 base64: 前缀）
  ENCRYPTION_CIPHER         默认 aes-256-gcm
  ENCRYPTION_PREVIOUS_KEYS  退役密钥，逗号分隔
  ENCRYPTION_DB_DRIVER      默认 mysql

退出码：0 成功 · 1 用法错误 · 2 配置或密码学错误
";

/// 用法错误。
const EXIT_USAGE: u8 = 1;
/// 配置或密码学错误。
const EXIT_CRYPTO: u8 = 2;

/// 打印用法，并带上项目宠物 —— 与 PHP 版安装时的提示一个用意。
fn print_usage() {
    println!("{}", encryptable::pet::ASCII);
    println!();
    print!("{USAGE}");
}

/// 版本信息。`名称 版本`（git 惯例的一行式），随后附上宠物。
fn print_version() {
    println!("encryptable {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("{}", encryptable::pet::ASCII);
    println!();
    println!("{}", encryptable::pet::TAGLINE);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        print_version();
        return ExitCode::SUCCESS;
    }

    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return if args.is_empty() {
            ExitCode::from(EXIT_USAGE)
        } else {
            ExitCode::SUCCESS
        };
    }

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(msg)) => {
            eprint_pet();
            eprintln!("用法错误：{msg}");
            eprintln!("\n用 `encryptable --help` 查看完整说明。");
            ExitCode::from(EXIT_USAGE)
        }
        Err(CliError::Crypto(e)) => {
            eprint_pet();
            eprintln!("错误：{e}");
            ExitCode::from(EXIT_CRYPTO)
        }
    }
}

/// 报错时附上项目宠物 —— 但**只在交互式终端里**。
///
/// 脚本与 CI 会把 stderr 重定向进日志，往里塞七行 ASCII 图只会碍事；
/// `IsTerminal` 正好把这两种场景分开（同 `--color=auto` 的思路）。
/// 想在任何情况下都要形象，用 `encryptable pet`。
fn eprint_pet() {
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        eprintln!("{}", encryptable::pet::ASCII);
        eprintln!();
    }
}

/// CLI 错误：区分「用错了」与「跑失败了」，好给出不同退出码。
enum CliError {
    Usage(String),
    Crypto(Error),
}

impl From<Error> for CliError {
    fn from(e: Error) -> Self {
        Self::Crypto(e)
    }
}

/// 从环境变量取配置，密钥缺失时给出可操作的提示。
fn config() -> Result<EnvConfig, CliError> {
    let config = EnvConfig::from_env();
    if config.key().is_none() {
        return Err(CliError::Usage(
            "没有读到 ENCRYPTION_KEY。可以先跑 `encryptable keygen` 生成一把，\n\
             然后 `export ENCRYPTION_KEY=<那把密钥>`。"
                .into(),
        ));
    }
    Ok(config)
}

fn run(args: &[String]) -> Result<(), CliError> {
    let (command, rest) = args.split_first().expect("调用方已确保非空");

    // `pet` 不需要密钥，先放行
    if command == "pet" {
        println!("{}", encryptable::pet::ASCII);
        return Ok(());
    }
    if command == "keygen" {
        return keygen();
    }

    // 解析 --driver / --raw，其余是位置参数
    let mut driver: Option<DbDriver> = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--driver" => {
                let value = iter
                    .next()
                    .ok_or_else(|| CliError::Usage("--driver 后面要跟一个方言名".into()))?;
                driver = Some(DbDriver::from_name(value));
            }
            "--raw" => {}
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!("不认识的选项 {other}")));
            }
            other => positional.push(other),
        }
    }

    let config = config()?;

    match command.as_str() {
        "encrypt" => {
            let value = operand(&positional, "encrypt")?;
            println!("{}", AeadEncrypter::new(&config)?.encrypt(value)?);
        }
        "decrypt" => {
            let value = operand(&positional, "decrypt")?;
            println!("{}", AeadEncrypter::new(&config)?.decrypt_text(value)?);
        }
        "rotate" => {
            let value = operand(&positional, "rotate")?;
            println!(
                "{}",
                AeadEncrypter::new(&config)?.rotate_to_current_key(value)?
            );
        }
        "db-encrypt" => {
            let value = operand(&positional, "db-encrypt")?;
            println!("{}", db_config(&config)?.encrypt(value)?);
        }
        "db-decrypt" => {
            let value = operand(&positional, "db-decrypt")?;
            println!("{}", db_config(&config)?.decrypt(value)?);
        }
        "sql" => {
            let column = operand(&positional, "sql")?;
            let encrypter = db_config(&config)?;
            let driver = driver.unwrap_or_else(|| encrypter.driver());
            eprintln!(
                "注意：该表达式会把主密钥嵌入 SQL 文本，因而会进入慢查询日志与\n\
                 pg_stat_statements。过滤条件请改用 `db-encrypt` 的结果做参数绑定。"
            );
            println!("{}", encrypter.decrypt_expr(column, driver)?);
        }
        other => return Err(CliError::Usage(format!("不认识命令 {other}"))),
    }

    Ok(())
}

/// DB 侧需要确定性密码。用户若把 `ENCRYPTION_CIPHER` 留在默认的 GCM 上，
/// 这里补一个明确的提示，而不是丢了钥匙再捡回来。
fn db_config(config: &EnvConfig) -> Result<DbEncrypter, CliError> {
    match DbEncrypter::new(config) {
        Ok(e) => Ok(e),
        Err(Error::CipherNotUsable { .. }) => Err(CliError::Usage(
            "DB 侧需要确定性密码。请设置 ENCRYPTION_CIPHER=aes-256-ecb —— \
             应用侧的默认值 aes-256-gcm 每次产出不同密文，无法用于等值查询。"
                .into(),
        )),
        Err(e) => Err(e.into()),
    }
}

/// 取位置参数；没有则回退到读 stdin，便于管道使用。
fn operand<'a>(positional: &[&'a str], command: &str) -> Result<&'a str, CliError> {
    if let Some(v) = positional.first() {
        return Ok(v);
    }

    // stdin 只有在不是终端时才读，否则会静默挂住
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(CliError::Usage(format!(
            "{command} 需要一个参数，或者把内容用管道传进来"
        )));
    }

    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| CliError::Usage(format!("读 stdin 失败：{e}")))?;

    // 借用问题：这里必须泄漏成 'static，量极小且进程随即结束
    Ok(Box::leak(
        buf.trim_end_matches('\n').to_owned().into_boxed_str(),
    ))
}

/// 生成一把新密钥，同时给出可直接使用的写法。
///
/// 只列**真的能用**的两种形式。裸 base64 不能列：44 个字符按字面量算就是 44 字节，
/// 不是 32 字节，解析时会被长度校验拒掉 —— 而那正是 `openssl rand -base64 32`
/// 的输出形态，最容易让人以为可以直接粘。要放 base64 就得带上 `base64:` 前缀，
/// 少了那个前缀它只是一串普通字符。
fn keygen() -> Result<(), CliError> {
    use aes_gcm::aead::OsRng;
    use aes_gcm::{Aes256Gcm, KeyInit as _};
    use base64::Engine as _;

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let bytes = key.as_slice();

    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);

    debug_assert_eq!(bytes.len(), 32);
    debug_assert_eq!(hex.len(), 64);

    println!("生成了一把 32 字节主密钥。以下两种写法等价，任选其一：\n");
    println!("  # 十六进制（64 个字符，也是 SQL 片段里用的表示）");
    println!("  export ENCRYPTION_KEY={hex}");
    println!();
    println!("  # base64 前缀形式（注意 base64: 前缀不能省）");
    println!("  export ENCRYPTION_KEY=base64:{b64}");
    println!();
    println!("  裸 base64（{b64}）");
    println!("  不能直接用 —— 44 个字符按字面量算是 44 字节，长度校验会拒绝它。");
    println!();
    println!("{}", encryptable::pet::ASCII);

    Ok(())
}
