// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! DB 侧加密：确定性 ECB，外加让**数据库自己**解密的 SQL 片段。
//!
//! ```text
//! 载荷 = base64( 版本(1B) || AES-ECB-PKCS7(明文) )
//! 版本 = 0x04（当前，HKDF 子密钥）| 0x02（1.2.x 旧格式，主密钥直用，只读）
//! ```
//!
//! # 为什么这条路径不是 AEAD
//!
//! 应用侧只收 AEAD，这里却只能用 ECB —— 不是历史包袱，是数据库能力的硬边界：
//! MySQL 的 `AES_DECRYPT` 与 pgcrypto 的 `decrypt` 都只认 ECB/CBC，**没有 GCM**。
//! 要让 `WHERE` 里能比对密文列，就只能用确定性模式。
//!
//! 代价必须说清楚：同样明文恒定产出同样密文，于是**频率分析可行**。低基数的列
//! （性别、状态、省份）加密后几乎等于没加密。这条路径只该用在「必须能按原值查询」
//! 的列上，其余一律走应用侧。
//!
//! # 为什么是子密钥
//!
//! 这条路径对任意明文块给出 `E_K(块)` —— 它就是一台加密预言机，主密钥绝不能
//! 直接喂给它（完整论证见 crate 文档「两条路径」一节）。当前格式（`0x04`）用的是
//! HKDF 派生的 **DB 侧子密钥**；`0x02` 旧格式保留只读，新写入不再产生。
//!
//! # 密文前不放 HMAC 前缀
//!
//! 在密文前面压一段 HMAC 好让 SQL 用 `SUBSTRING` 剥掉，看起来像认证，其实对这条
//! 路径没有任何安全作用（数据库从不校验它，能加密的人自然也算得出）。于是不放，
//! 那个位置让给版本字节：SQL 只需 `SUBSTRING(..., 2)`。

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::cipher::Cipher;
use crate::config::{DbDriver, EncryptableConfig};
use crate::encrypter::aead::MIN_B64_LEN as AEAD_MIN_B64_LEN;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::support::subkeys;

/// DB 侧载荷当前写出的格式字节。应用侧是 [`0x03`](crate::encrypter::aead::VERSION)。
pub const VERSION: u8 = 0x04;

/// DB 侧载荷的旧格式字节（1.2.x，主密钥直用）。**只读** —— 新密文不会再用它。
pub const LEGACY_VERSION: u8 = 0x02;

/// 块长度，AES 恒为 16。
const BLOCK: usize = 16;

/// 载荷最小长度：版本 + 一个满块。
const MIN_LEN: usize = 1 + BLOCK;

/// 真载荷 base64 后的最短字符数：`ceil(MIN_LEN / 3) × 4`（17 字节 ⇒ 24 字符）。
const MIN_B64_LEN: usize = MIN_LEN.div_ceil(3) * 4;

/// 确定性加密器。
///
/// 只认 ECB 密码。这一点在构造时就卡死 —— 配了 GCM 却走这条路径是**静默失效**：
/// 密文每次不同，等值查询永远匹配不上，而报错都不会有一个。
#[derive(Clone)]
pub struct DbEncrypter {
    /// 当前格式（0x04）：HKDF 派生的 DB 侧子密钥。
    current: EcbCipher,
    /// 旧格式（0x02）：主密钥原样，只读。
    legacy: EcbCipher,
    /// 主密钥本体。`key_hex()` 与 `decrypt_expr` 的迁移分支要用。
    key: Key,
    /// 派生的子密钥。`derived_key_hex()` 要用。
    derived: Key,
    driver: DbDriver,
}

#[derive(Clone)]
enum EcbCipher {
    Aes256(Box<Aes256>),
    Aes128(Box<Aes128>),
}

impl EcbCipher {
    /// 就地加密每个 16 字节分组。`data.len()` 必须是 16 的整数倍。
    fn encrypt_blocks(&self, data: &mut [u8]) {
        for chunk in data.as_chunks_mut::<BLOCK>().0 {
            let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
            match self {
                Self::Aes256(c) => c.encrypt_block(block),
                Self::Aes128(c) => c.encrypt_block(block),
            }
        }
    }

    /// 就地解密每个 16 字节分组。`data.len()` 必须是 16 的整数倍。
    fn decrypt_blocks(&self, data: &mut [u8]) {
        for chunk in data.as_chunks_mut::<BLOCK>().0 {
            let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
            match self {
                Self::Aes256(c) => c.decrypt_block(block),
                Self::Aes128(c) => c.decrypt_block(block),
            }
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Aes256(_) => Cipher::Aes256Ecb.as_str(),
            Self::Aes128(_) => Cipher::Aes128Ecb.as_str(),
        }
    }
}

impl DbEncrypter {
    /// 从配置构造，构造时即校验密码必须是确定性的。
    ///
    /// # Errors
    ///
    /// - [`Error::MissingKey`] —— 配置里没有密钥
    /// - [`Error::MissingCipher`] / [`Error::UnsupportedCipher`] —— 密码为空或不在白名单内
    /// - [`Error::CipherNotUsable`] —— 配了非确定性密码（本路径只收 ECB）
    /// - [`Error::InvalidKeyBase64`] —— `base64:` 前缀后面的内容解不开
    /// - [`Error::KeyLength`] —— 密钥字节数与密码要求不符
    pub fn new<C: EncryptableConfig + 'static>(config: &C) -> Result<Self> {
        let cipher = if config.cipher().trim().is_empty() {
            return Err(Error::MissingCipher);
        } else {
            config.cipher().parse::<Cipher>()?
        };

        if !cipher.is_deterministic() {
            return Err(Error::CipherNotUsable {
                cipher: cipher.to_string(),
                accepted: "aes-256-ecb, aes-128-ecb",
                reason: "DB 侧要求确定性加密，否则同样的明文每次产出不同密文，\
                         等值查询永远匹配不上；需要认证的存储场景请走应用侧",
            });
        }

        let raw_key = config.key().ok_or(Error::MissingKey)?;
        let key = Key::parse(raw_key, cipher)?;
        let derived = subkeys::derive(&key, subkeys::DB_INFO, cipher)?;

        // DB 路径没有密钥环：SQL 片段与 `decrypt` 都只认构造时这一把。
        // 配置里带着 previous_keys 一定是运维把应用侧的轮换剧本套用过来了 ——
        // 那些列的 SQL 侧会静默变 NULL（MySQL）或直接报错（pgcrypto），
        // 值得在启动日志里响亮一次。不报错：同一份 EnvConfig 喂两条路径是常见写法。
        if !config.previous_keys().is_empty() {
            eprintln!(
                "encryptable：DbEncrypter 忽略 previous_keys —— DB 路径没有密钥环，\
                 要求 DB 自解的列请重新加密（重写为新主密钥的密文），详见 README「密钥轮换」一节"
            );
        }

        let build = |k: &Key| -> Result<EcbCipher> {
            Ok(match cipher {
                Cipher::Aes256Ecb => EcbCipher::Aes256(Box::new(
                    Aes256::new_from_slice(k.as_bytes())
                        .map_err(|e| Error::Encrypt(e.to_string()))?,
                )),
                Cipher::Aes128Ecb => EcbCipher::Aes128(Box::new(
                    Aes128::new_from_slice(k.as_bytes())
                        .map_err(|e| Error::Encrypt(e.to_string()))?,
                )),
                // is_deterministic() 已经挡过
                other => return Err(Error::UnsupportedCipher(other.to_string())),
            })
        };

        let current = build(&derived)?;
        let legacy = build(&key)?;

        Ok(Self {
            current,
            legacy,
            key,
            derived,
            driver: config.db_driver(),
        })
    }

    /// 使用的密码名。
    pub fn cipher_name(&self) -> &'static str {
        self.current.name()
    }

    /// SQL 片段的目标方言。
    pub fn driver(&self) -> DbDriver {
        self.driver
    }

    /// 加密一段明文（写入路径）。
    ///
    /// 入参是字符串而不是类型信封：SQL 需要看到**逐字节的原值**，套一层类型字节
    /// 会让数据库里躺着的明文带上信封头，`WHERE` 比对也就对不上了。
    ///
    /// # Errors
    ///
    /// - [`Error::WrongFormat`] —— 输入是**应用侧**密文（格式字节 `0x01` / `0x03`）。
    ///   这条是刻意拦的：不拦就会把应用侧密文当明文再加密一遍，静默产生解不开的数据。
    ///   判定带长度闸（真应用侧载荷 base64 后恒 ≥ 40 字符），短输入不误伤；
    ///   超过 40 字符又恰好形状吻合的输入仍可能被误拦 —— 那是形状判定的固有上限，
    ///   绕过口是 [`seal`](Self::seal)
    /// - [`Error::Encrypt`] —— 底层 ECB 加密失败
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        // 只拦「看起来是应用侧载荷」的输入，而且只在长度**可能**是真的应用侧
        // 载荷时才做形状判定。没有这道长度闸，`AQ`/`AR`/`AS`/`AT` 开头的合法
        // 业务码（首字节恒为 0x01，由前两个字符唯一决定）会被**永久误拒**，
        // 而且 DB 侧此前没有绕过口。≥40 字符的长业务码若形状恰好吻合仍会被拒，
        // 那是形状判定的固有上限 —— 绕过口是 seal()。
        if plaintext.len() >= AEAD_MIN_B64_LEN
            && let Some(found) = self.format_byte(plaintext)
            && (found == crate::encrypter::aead::VERSION
                || found == crate::encrypter::aead::LEGACY_VERSION)
        {
            return Err(Error::WrongFormat {
                found,
                expected: VERSION,
            });
        }

        self.seal(plaintext)
    }

    /// 无条件加密，不做「是否已是应用侧密文」的形状判定。
    ///
    /// 形状判定有假阳性上限（见 [`encrypt`](Self::encrypt)），这个方法就是那道
    /// 上限的绕过口：明确知道输入是明文时用它，任何输入都会照常加密。
    ///
    /// # Errors
    ///
    /// 底层 ECB 加密失败时返回 [`Error::Encrypt`]。
    pub fn seal(&self, plaintext: &str) -> Result<String> {
        let mut data = pkcs7_pad(plaintext.as_bytes());
        self.current.encrypt_blocks(&mut data);

        let mut payload = Vec::with_capacity(1 + data.len());
        payload.push(VERSION);
        payload.extend_from_slice(&data);

        Ok(base64::engine::general_purpose::STANDARD.encode(&payload))
    }

    /// 解密自己产出的载荷（当前格式与旧格式都认）。用于迁移与 CLI，
    /// **不用于查询** —— 查询请用 [`decrypt_expr`](Self::decrypt_expr) 让数据库自己解。
    ///
    /// # Errors
    ///
    /// - [`Error::Base64`] —— 载荷不是合法 base64
    /// - [`Error::WrongFormat`] —— 载荷是**应用侧**密文，走错了加密器
    /// - [`Error::Decrypt`] —— 版本字节陌生、载荷太短/不是块长的整数倍（这些是
    ///   **形状**层面、攻击者自己就能算出的判据），或解密之后补位/编码校验失败
    ///
    /// # 为什么解密之后的失败只有一条消息
    ///
    /// 补位长度非法、补位字节不自洽、结果不是合法 UTF-8 —— 这三者曾经各有
    /// 一条可区分的错误消息。ECB 没有认证，在**攻击者能触发解密**（把加密值当
    /// 不透明 token 收进来）的场景里，可区分的失败就是一个 padding oracle：
    /// 逐字节改密文、看错误分类，就能还原出 `D_K(·)`。现在它们折叠成同一条
    /// [`Error::Decrypt`]，与「密钥错」也不可区分 —— 这正是 GCM 侧一贯的做法
    /// （tag 校验失败只有一个理由）。
    ///
    /// 相应地：**密钥错**通常不在这条清单里。ECB 没有认证，错密钥解出来多半是
    /// 乱码字节 —— 补位/编码校验会碰巧挡住一部分，剩下的也可能原样返回一段
    /// 看起来正常的乱码。这是 ECB 的固有性质，不是实现缺陷。
    pub fn decrypt(&self, payload: &str) -> Result<String> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|e| Error::Base64(e.to_string()))?;

        // 与 AeadEncrypter::decrypt 同样的顺序：格式字节优先于长度，
        // 这样走错加密器得到的是「格式不对」而不是「载荷太短」。
        // 这两类都是形状判据（不依赖密钥），保留具体消息不构成 oracle。
        let version = match decoded.first() {
            Some(&VERSION) | Some(&LEGACY_VERSION) => decoded[0],
            Some(&found)
                if found == crate::encrypter::aead::VERSION
                    || found == crate::encrypter::aead::LEGACY_VERSION =>
            {
                return Err(Error::WrongFormat {
                    found,
                    expected: VERSION,
                });
            }
            Some(&found) => {
                return Err(Error::Decrypt(format!(
                    "陌生的格式字节 0x{found:02x}，期望 0x{VERSION:02x} 或 0x{LEGACY_VERSION:02x}"
                )));
            }
            None => return Err(Error::Decrypt("载荷为空".into())),
        };

        if decoded.len() < MIN_LEN {
            return Err(Error::Decrypt(format!(
                "载荷只有 {} 字节，短于最小的 {MIN_LEN} 字节",
                decoded.len()
            )));
        }

        // 两代密钥各解各的：0x02 用主密钥原样，0x04 用 HKDF 子密钥。
        let cipher = match version {
            LEGACY_VERSION => &self.legacy,
            _ => &self.current,
        };

        // 解密之后的失败一律折叠成同一条消息（见上方「为什么」）。
        let opaque = || Error::Decrypt("解密失败（补位或编码校验不通过）".into());

        // 就地处理 `decoded`，不再另拷两份 —— 并且裹上 `Zeroizing`：
        // 解密之后这段缓冲里躺着的是明文，出错提前返回时也不该裸着被丢弃。
        let mut data = Zeroizing::new(decoded);
        let plain_len = {
            let body = &mut data[1..];
            if !body.len().is_multiple_of(BLOCK) {
                return Err(Error::Decrypt(format!(
                    "密文 {} 字节，不是 {BLOCK} 的整数倍",
                    body.len()
                )));
            }

            cipher.decrypt_blocks(body);
            // pkcs7_unpad 的具体原因（长度非法 / 字节不自洽）对调用方隐藏 ——
            // 那是 oracle 的两半。
            pkcs7_unpad(body).map_err(|_| opaque())?.len()
        };

        data.truncate(1 + plain_len); // 截掉 PKCS#7 补位
        data.remove(0); // 去掉版本字节（一次 memmove，不额外分配）

        String::from_utf8(std::mem::take(&mut *data)).map_err(|_| opaque())
    }

    /// 廉价判定：形状上像不像 DB 侧密文（含旧格式）。
    pub fn is_encrypted(&self, value: &str) -> bool {
        matches!(
            self.format_byte(value),
            Some(VERSION) | Some(LEGACY_VERSION)
        )
    }

    /// 取 base64 解出后的首字节，形状不对则 `None`。
    fn format_byte(&self, value: &str) -> Option<u8> {
        // 长度前置：短于真载荷最短 base64 长度的输入不可能解出 `MIN_LEN` 字节，
        // 连解码都不用试（base64 的 `decode` 会先分配再校验，见其实现）。
        if value.len() < MIN_B64_LEN || !value.len().is_multiple_of(4) {
            return None;
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value)
            .ok()?;
        if decoded.len() < MIN_LEN {
            return None;
        }
        Some(decoded[0])
    }

    /// 生成让数据库自己解密的 SQL 表达式。
    ///
    /// ⚠️ **这个片段把密钥以十六进制嵌进了 SQL 文本**，于是它会出现在慢查询日志、
    /// `pg_stat_statements`、以及任何记录语句的地方。只在
    /// 「`SELECT` 列表里要看到明文」或报表场景用；过滤条件请改用等值比对 ——
    /// 先用 [`encrypt`](Self::encrypt) 算出密文再当参数绑定：
    ///
    /// ```sql
    /// SELECT id FROM users WHERE phone = ?     -- 绑定 encrypter.encrypt(输入)
    /// ```
    ///
    /// 这样既不需要在 SQL 里放密钥，也能吃上该列上的索引。
    ///
    /// 表达式按格式字节分派：`0x04`（当前）用子密钥、`0x02`（1.2.x 旧数据）用
    /// 主密钥原样解 —— 迁移期的混合列一条语句就能全读。旧数据搬完（重加密为
    /// `0x04`）后可以换成只含子密钥的定制语句，把主密钥从 SQL 里彻底拿掉；
    /// 子密钥的 hex 由 [`derived_key_hex`](Self::derived_key_hex) 提供。
    ///
    /// 密钥用 **hex** 而非带引号的字符串：片段里因此不含任何 `'` 转义面，
    /// 转义漏一个字符导致注入的可能性也就不存在了。
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidColumnRef`] —— 列名不匹配 `^[A-Za-z_][A-Za-z0-9_.]*$`，
    ///   或含空的点分段（`a..b`、`a.`）。这是这条路径上唯一的注入面，所以是白名单不是转义
    ///
    /// 密钥长度、密码可用性等配置错误在构造时就已经报过了，这里不会再报。
    pub fn decrypt_expr(&self, column: &str, driver: DbDriver) -> Result<String> {
        validate_column(column)?;
        let current = self.derived_key_hex();
        let current = current.as_str();
        let legacy = self.key.to_hex();
        let legacy = legacy.as_str();

        Ok(match driver {
            DbDriver::Mysql => format!(
                "CASE SUBSTRING( FROM_BASE64({column}), 1, 1 ) WHEN 0x04 THEN CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64({column}), 2 ), UNHEX('{current}') ) USING 'UTF8' ) WHEN 0x02 THEN CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64({column}), 2 ), UNHEX('{legacy}') ) USING 'UTF8' ) ELSE NULL END"
            ),
            DbDriver::Postgres => format!(
                "CASE get_byte( decode({column}, 'base64'), 0 ) WHEN 4 THEN convert_from( decrypt( substring( decode({column}, 'base64') from 2 ), '\\x{current}'::bytea, 'aes-ecb' ), 'UTF8' ) WHEN 2 THEN convert_from( decrypt( substring( decode({column}, 'base64') from 2 ), '\\x{legacy}'::bytea, 'aes-ecb' ), 'UTF8' ) ELSE NULL END"
            ),
        })
    }

    /// 用构造时的方言生成 SQL 表达式。
    ///
    /// # Errors
    ///
    /// 与 [`decrypt_expr`](Self::decrypt_expr) 相同：[`Error::InvalidColumnRef`]。
    pub fn decrypt_expr_default(&self, column: &str) -> Result<String> {
        let driver = self.driver;
        self.decrypt_expr(column, driver)
    }

    /// 主密钥的十六进制表示（与配置里的密钥等价，可回喂
    /// [`Key::parse`](crate::key::Key::parse)）。
    ///
    /// 迁移期的 `0x02` 分支要用它 —— 但那是主密钥本体，别把它留在日志里。
    /// 当前格式（`0x04`）用 [`derived_key_hex`](Self::derived_key_hex)。
    pub fn key_hex(&self) -> Zeroizing<String> {
        self.key.to_hex()
    }

    /// 当前格式（`0x04`）所用的 **DB 侧子密钥** 的十六进制表示。
    ///
    /// [`decrypt_expr`](Self::decrypt_expr) 已把两代密钥都内嵌进 CASE 表达式，
    /// 这个方法只给「旧数据搬完、想手工拼只含子密钥的语句」的场景用。
    pub fn derived_key_hex(&self) -> Zeroizing<String> {
        self.derived.to_hex()
    }
}

impl std::fmt::Debug for DbEncrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbEncrypter")
            .field("cipher", &self.cipher_name())
            .field("driver", &self.driver)
            .finish()
    }
}

/// PKCS#7 补位：补 `n` 个值为 `n` 的字节，`n ∈ 1..=16`。
///
/// 对齐时也要补满一整块 —— 否则去位时就分不清「末尾那几个字节是补位还是数据」。
/// MySQL 与 pgcrypto 用的都是这个方案，所以 Rust 这边写出来的字节它们能解。
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = BLOCK - (data.len() % BLOCK);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

/// PKCS#7 去位，并校验补位字节自洽。
fn pkcs7_unpad(data: &[u8]) -> Result<&[u8]> {
    let &last = data
        .last()
        .ok_or_else(|| Error::Decrypt("补位去位时载荷为空".into()))?;
    let pad = usize::from(last);

    if pad == 0 || pad > BLOCK || pad > data.len() {
        return Err(Error::Decrypt(format!("补位长度 {pad} 非法")));
    }

    let split = data.len() - pad;
    if !data[split..].iter().all(|&b| b == last) {
        return Err(Error::Decrypt("补位字节不自洽".into()));
    }

    Ok(&data[..split])
}

/// 列引用白名单校验。
///
/// 手写而不引 `regex`：判据就是「首字符字母或下划线，其余字母数字下划线或点，
/// 长度 1..=63」，几十个字节的事，不值得为它多一个依赖。允许点号是为了
/// `users.phone` 这种带表名的写法。
fn validate_column(column: &str) -> Result<()> {
    let bad = || Error::InvalidColumnRef(column.to_owned());

    if column.is_empty() || column.len() > 63 {
        return Err(bad());
    }

    let mut bytes = column.bytes();
    let first = bytes.next().ok_or_else(bad)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(bad());
    }

    if !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.') {
        return Err(bad());
    }

    // 点号必须夹在两段之间：`users.phone` 合法，`a.b.` / `a..b` 不是合法标识符。
    // 常见的 `^[A-Za-z_][A-Za-z0-9_.]*$` 写法会放行后两者，这里收紧 ——
    // 放行它们没有任何好处，而收紧不可能误伤真实的列名。
    if column.split('.').any(str::is_empty) {
        return Err(bad());
    }

    Ok(())
}

#[cfg(test)]
mod tests;
