// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 应用侧加密：随机 nonce 的 AEAD 信封。
//!
//! ```text
//! 载荷 = base64( 版本(1B) || nonce(12B) || AES-GCM 密文 || tag(16B) )
//! 明文 = 类型信封( tag(1B) || 载荷 )        见 crate::serializer
//! AAD  = 版本字节
//! ```
//!
//! 与 PHP 版的信封相比，这里**去掉了三样东西**：
//!
//! - **手工 HMAC**：GCM 的 tag 本身就是认证，再叠一层 HMAC 只是把同一件事做两遍。
//! - **`crypt:` 脏位**：PHP 靠这个明文前缀判断「密钥对不对」。GCM 的 tag 校验失败
//!   就是密钥不对或密文被改，由密码学保证，不靠约定。
//! - **非 AEAD 分支**：CBC/ECB 在这条路径上不再支持。没有认证的密文会在解密时
//!   静默产出垃圾，这条路径只收 AEAD。

use aes_gcm::aead::{Aead, AeadCore, OsRng, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;

use crate::cipher::Cipher;
use crate::config::EncryptableConfig;
use crate::error::{Error, Result};
use crate::key::{Key, KeyRing};
use crate::serializer::Value;

/// 应用侧载荷的格式字节。DB 侧是 [`0x02`](crate::encrypter::DbEncrypter::VERSION)，
/// 两者不可互换。
pub const VERSION: u8 = 0x01;

/// GCM nonce 长度，RFC 5116 推荐值。
const NONCE_LEN: usize = 12;

/// GCM tag 长度。
const TAG_LEN: usize = 16;

/// 载荷最小长度：版本 + nonce + tag（空明文）。
const MIN_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

/// 应用侧加密器。
///
/// 配置在构造时就被解析成一串密钥，之后不再读环境、不再解析字符串。
///
/// 密钥环上**每一把钥匙各自的 cipher 也在构造时一次建好**：AES 的密钥调度是
/// 每次解密都要付的固定开销，放在解密循环里重建等于每请求重算一遍。
#[derive(Clone)]
pub struct AeadEncrypter {
    /// 与 `ring` 索引对齐：`ciphers[i]` 是 `ring` 第 i 把钥匙的 cipher。
    /// `ciphers[0]` 即主密钥的 cipher，加密只用它。
    ciphers: Vec<GcmCipher>,
    ring: KeyRing,
    /// 密码名，构造时定下来（原本靠 match `cipher` 字段推，现在直接存）。
    name: &'static str,
}

/// 底层 GCM 实例。
///
/// `Aes256Gcm` 与 `Aes128Gcm` 是两个不同类型，只能这样分支持有。
#[derive(Clone)]
enum GcmCipher {
    Aes256(Box<Aes256Gcm>),
    Aes128(Box<Aes128Gcm>),
}

impl GcmCipher {
    /// 按密码与密钥字节建一个 GCM 实例。
    ///
    /// 密钥长度此前已由 [`Key::parse`](crate::key::Key::parse) 校验过，这里的
    /// `new_from_slice` 正常不会失败；真失败了也是配置错，照实报出去。
    fn new(cipher: Cipher, key: &[u8]) -> Result<Self> {
        Ok(match cipher {
            Cipher::Aes256Gcm => Self::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).map_err(|e| Error::Encrypt(e.to_string()))?,
            )),
            Cipher::Aes128Gcm => Self::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|e| Error::Encrypt(e.to_string()))?,
            )),
            other => return Err(Error::UnsupportedCipher(other.to_string())),
        })
    }

    fn seal(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let aad = [VERSION];
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };
        match self {
            Self::Aes256(c) => c
                .encrypt(Nonce::from_slice(nonce), payload)
                .map_err(|e| Error::Encrypt(e.to_string())),
            Self::Aes128(c) => c
                .encrypt(Nonce::from_slice(nonce), payload)
                .map_err(|e| Error::Encrypt(e.to_string())),
        }
    }

    /// 认证失败返回 `None` —— 调用方要拿它去试环上的下一把钥匙，
    /// 而不是立刻把错误抛给用户。
    fn open(&self, nonce: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let aad = [VERSION];
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };
        match self {
            Self::Aes256(c) => c.decrypt(Nonce::from_slice(nonce), payload).ok(),
            Self::Aes128(c) => c.decrypt(Nonce::from_slice(nonce), payload).ok(),
        }
    }
}

impl AeadEncrypter {
    /// 从配置构造，构造时即校验密码与密钥。
    ///
    /// 校验放在构造而不是首次使用：配错了就该在启动时炸，而不是在某个深夜的
    /// 请求路径上才失败。
    ///
    /// # Errors
    ///
    /// - [`Error::MissingKey`] —— 配置里没有密钥
    /// - [`Error::MissingCipher`] / [`Error::UnsupportedCipher`] —— 密码为空或不在白名单内
    /// - [`Error::CipherNotUsable`] —— 配了非 AEAD 密码（本路径只收 GCM）
    /// - [`Error::InvalidKeyBase64`] —— `base64:` 前缀后面的内容解不开
    /// - [`Error::KeyLength`] —— 密钥字节数与密码要求不符（主密钥与退役密钥一并校验）
    pub fn new<C: EncryptableConfig + 'static>(config: &C) -> Result<Self> {
        let cipher = Cipher::from_str_checked(config.cipher())?;

        if !cipher.is_aead() {
            return Err(Error::CipherNotUsable {
                cipher: cipher.to_string(),
                accepted: "aes-256-gcm, aes-128-gcm",
                reason: "应用侧要求带认证的加密；无认证的密文被篡改时会静默产出垃圾，\
                         而等值查询所需的确定性加密请走 DB 侧",
            });
        }

        let raw_key = config.key().ok_or(Error::MissingKey)?;
        let primary = Key::parse(raw_key, cipher)?;

        // 退役密钥同样按主密码的长度校验 —— 环上所有钥匙必须等长，
        // 否则「换一把钥匙解开旧密文」这件事在密码层就不成立。
        let previous = config
            .previous_keys()
            .iter()
            .filter(|k| !k.trim().is_empty())
            .map(|k| Key::parse(k, cipher))
            .collect::<Result<Vec<_>>>()?;

        let ring = KeyRing::new(primary, previous);

        // 环上**每一把**钥匙各建一个 cipher，而不是只建主密钥那个。
        //
        // 原本只在构造时建主密钥的，解密时再按需重建 —— 那么每次解密都要为
        // 环上每一把钥匙重做一次 AES 密钥调度（外加一次 Box 分配），单密钥部署
        // 下等于每请求白算一遍。密钥调度是固定开销，一次性付掉即可。
        let mut ciphers = Vec::with_capacity(ring.len());
        for key in ring.iter() {
            ciphers.push(GcmCipher::new(cipher, key.as_bytes())?);
        }

        Ok(Self {
            ciphers,
            ring,
            name: cipher.as_str(),
        })
    }

    /// 使用的密码名。
    pub fn cipher_name(&self) -> &'static str {
        self.name
    }

    /// 主密钥的 cipher。加密只用它。
    ///
    /// 不变量：`KeyRing::new` 保证环上至少有一把钥匙，而 `ciphers` 与环等长，
    /// 所以下标 0 必然存在。
    fn primary_cipher(&self) -> &GcmCipher {
        &self.ciphers[0]
    }

    /// 环上钥匙数量（含主密钥）。
    pub fn ring_len(&self) -> usize {
        self.ring.len()
    }

    /// 加密一个值。
    ///
    /// 已经是本格式的密文则**原样返回**，不会二次加密。判定方式是试着解开它 ——
    /// 光看形状会把「base64 解出来首字节恰好是 0x01 的明文」误判成密文然后存进去，
    /// 那正是 PHP 版踩过的坑。
    ///
    /// # Errors
    ///
    /// 只在底层 AEAD 加密失败时返回 [`Error::Encrypt`]（明文超长等）。输入是
    /// 别的格式的密文**不会**报错 —— 那会被当作普通明文照常加密。
    pub fn encrypt(&self, value: impl Into<Value>) -> Result<String> {
        let value = value.into();

        // 两阶段判定，两边的好处都要：
        //
        // ① `is_encrypted` 是廉价的形状判定（一次 base64 解码尝试）。明文通常
        //    根本不是合法 base64，到这就被挡掉，不会白白做一次 GCM 解封。
        // ② 形状通过之后才真的去认证一次。**不能只做形状判定** —— 一段 base64
        //    解出来首字节恰好是 0x01 的明文会被误判成密文然后直接存库，从此
        //    解不开。那正是 PHP 版踩过的坑，第二阶段专治这个假阳性。
        if let Value::String(ref s) = value
            && self.is_encrypted(s)
            && self.decrypt(s).is_ok()
        {
            return Ok(s.clone());
        }

        self.seal(value)
    }

    /// 无条件加密，不做「是否已是密文」的判定。
    ///
    /// 只在明确知道输入是明文时用。重复加密同一段明文是完全合法的 ——
    /// nonce 随机会让两次结果不同。
    ///
    /// # Errors
    ///
    /// 底层 AEAD 加密失败时返回 [`Error::Encrypt`]（明文超长等）。不会因为输入
    /// 看起来像密文而失败。
    pub fn seal(&self, value: impl Into<Value>) -> Result<String> {
        let plaintext = value.into().encode();

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.primary_cipher().seal(&nonce, &plaintext)?;

        let mut payload = Vec::with_capacity(MIN_LEN + ciphertext.len());
        payload.push(VERSION);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(&payload))
    }

    /// 解密。密钥环上任意一把钥匙成功即可。
    ///
    /// 失败一律返回 [`Error::Decrypt`] —— **不做「失败就返回原文」的宽松回退**。
    /// 那种回退是明文被悄悄写进数据库的主要途径：加密列里躺着的明文看起来
    /// 和密文一模一样，直到某天有人审计。确实需要的话用
    /// [`decrypt_or_original`](Self::decrypt_or_original)，让这个决定显式出现在调用点。
    ///
    /// # Errors
    ///
    /// - [`Error::Base64`] —— 载荷不是合法 base64
    /// - [`Error::WrongFormat`] —— 载荷是 **DB 侧**密文（格式字节 `0x02`），走错了加密器
    /// - [`Error::Decrypt`] —— 版本字节陌生、长度不足，或密钥环上没有一把钥匙能解开
    /// - [`Error::Unserialize`] —— 解出来了，但类型信封读不出（类型字节陌生、载荷长度不符）
    pub fn decrypt(&self, payload: &str) -> Result<Value> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|e| Error::Base64(e.to_string()))?;

        // 先看格式字节再看长度：格式字节是更具体的诊断。反过来做的话，
        // 一段短的 DB 侧载荷会被报成「太短」，而真正的原因是走错了加密器。
        match decoded.first() {
            Some(&VERSION) => {}
            Some(&found) if found == crate::encrypter::DbEncrypter::VERSION => {
                return Err(Error::WrongFormat {
                    found,
                    expected: VERSION,
                });
            }
            Some(&found) => {
                return Err(Error::Decrypt(format!(
                    "陌生的格式字节 0x{found:02x}，期望 0x{VERSION:02x}"
                )));
            }
            None => return Err(Error::Decrypt("载荷为空".into())),
        }

        if decoded.len() < MIN_LEN {
            return Err(Error::Decrypt(format!(
                "载荷只有 {} 字节，短于最小的 {MIN_LEN} 字节",
                decoded.len()
            )));
        }

        let nonce = &decoded[1..1 + NONCE_LEN];
        let ciphertext = &decoded[1 + NONCE_LEN..];

        // 逐把钥匙试。cipher 在构造时就按环建好了，这里只剩一次 AEAD 解封。
        // 刻意不区分「是哪一把解开的」——调用方不需要知道，而把「第几把」
        // 泄出去等于泄了轮换进度。
        let mut opened = None;
        for cipher in &self.ciphers {
            if let Some(plain) = cipher.open(nonce, ciphertext) {
                opened = Some(plain);
                break;
            }
        }

        let plain =
            opened.ok_or_else(|| Error::Decrypt("密钥环上没有一把钥匙能解开这段密文".into()))?;

        Value::decode(&plain)
    }

    /// 解密并断言结果是字符串。
    ///
    /// # Errors
    ///
    /// 与 [`decrypt`](Self::decrypt) 相同，另加：解开但值不是字符串时返回
    /// [`Error::Decrypt`]（报文里写明实际类型）。
    pub fn decrypt_text(&self, payload: &str) -> Result<String> {
        match self.decrypt(payload)? {
            Value::String(s) => Ok(s),
            other => Err(Error::Decrypt(format!(
                "期望字符串，实际是 {}",
                other.type_name()
            ))),
        }
    }

    /// 宽松解密：解不开就原样返回输入。
    ///
    /// 这是 PHP 版的默认行为，在这里被降级成显式选项。只在「这一列是历史遗留的
    /// 混合列，可能既有密文也有明文」这类迁移场景下用。
    pub fn decrypt_or_original(&self, payload: &str) -> String {
        match self.decrypt(payload) {
            Ok(Value::String(s)) => s,
            Ok(other) => other.type_name().to_owned(),
            Err(_) => payload.to_owned(),
        }
    }

    /// 廉价判定：形状上像不像应用侧密文。
    ///
    /// 只做 base64 解码 + 版本字节 + 长度下限，**不碰密钥、不做认证**。代价是
    /// 会有假阳性：一段 base64 解出来首字节恰好是 `0x01` 的明文会被判为密文。
    /// 概率约 1/256 且还需整体是合法 base64，实践中可以接受；真正需要确定性答案
    /// 的场合请用 [`decrypt`](Self::decrypt)（它会真的认证一次）。
    pub fn is_encrypted(&self, value: &str) -> bool {
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
            return false;
        };
        decoded.len() >= MIN_LEN && decoded[0] == VERSION
    }

    /// 用环上任意钥匙解出明文，再用当前主密钥重新加密。
    ///
    /// 轮换的第三步：新数据已经用新主密钥写入，这个方法把存量数据一把一把搬过去。
    /// 输入本来就是明文时原样返回，方便在批处理里无脑调用。
    ///
    /// # Errors
    ///
    /// - 形状像密文但解不开：与 [`decrypt`](Self::decrypt) 相同的错误
    /// - 解开了但重新加密失败：[`Error::Encrypt`]
    ///
    /// 形状**不像**密文时原样返回，不报错。
    pub fn rotate_to_current_key(&self, payload: &str) -> Result<String> {
        if !self.is_encrypted(payload) {
            return Ok(payload.to_owned());
        }
        let value = self.decrypt(payload)?;
        self.seal(value)
    }

    /// ASNI 明文的密钥十六进制，给需要把密钥交给数据库的场景用。见
    /// [`DbEncrypter::decrypt_expr`](crate::encrypter::DbEncrypter::decrypt_expr)。
    pub fn primary_key_hex(&self) -> zeroize::Zeroizing<String> {
        self.ring.primary().to_hex()
    }
}

impl std::fmt::Debug for AeadEncrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadEncrypter")
            .field("cipher", &self.cipher_name())
            .field("ring_len", &self.ring.len())
            .finish()
    }
}

/// 校验密码字符串。
trait CipherExt {
    fn from_str_checked(s: &str) -> Result<Cipher>;
}

impl CipherExt for Cipher {
    fn from_str_checked(s: &str) -> Result<Cipher> {
        if s.trim().is_empty() {
            return Err(Error::MissingCipher);
        }
        s.parse()
    }
}

#[cfg(test)]
mod tests;
