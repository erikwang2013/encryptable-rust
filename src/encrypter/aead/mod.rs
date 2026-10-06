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
#[derive(Clone)]
pub struct AeadEncrypter {
    cipher: GcmCipher,
    ring: KeyRing,
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
        let gcm = match cipher {
            Cipher::Aes256Gcm => GcmCipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(ring.primary().as_bytes())
                    .map_err(|e| Error::Encrypt(e.to_string()))?,
            )),
            Cipher::Aes128Gcm => GcmCipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(ring.primary().as_bytes())
                    .map_err(|e| Error::Encrypt(e.to_string()))?,
            )),
            // is_aead() 已经挡过，这里不可达
            other => {
                return Err(Error::UnsupportedCipher(other.to_string()));
            }
        };

        Ok(Self { cipher: gcm, ring })
    }

    /// 使用的密码名。
    pub fn cipher_name(&self) -> &'static str {
        match self.cipher {
            GcmCipher::Aes256(_) => Cipher::Aes256Gcm.as_str(),
            GcmCipher::Aes128(_) => Cipher::Aes128Gcm.as_str(),
        }
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
    pub fn encrypt(&self, value: impl Into<Value>) -> Result<String> {
        let value = value.into();

        if let Value::String(ref s) = value
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
    pub fn seal(&self, value: impl Into<Value>) -> Result<String> {
        let plaintext = value.into().encode();

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.seal(&nonce, &plaintext)?;

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

        // 逐把钥匙试。这里刻意不区分「哪把钥匙解开的」——调用方不需要知道，
        // 而把「是第几把」泄出去等于泄了轮换进度。
        let mut opened = None;
        for key in self.ring.iter() {
            let gcm = match self.cipher {
                GcmCipher::Aes256(_) => Aes256Gcm::new_from_slice(key.as_bytes())
                    .ok()
                    .map(|c| GcmCipher::Aes256(Box::new(c))),
                GcmCipher::Aes128(_) => Aes128Gcm::new_from_slice(key.as_bytes())
                    .ok()
                    .map(|c| GcmCipher::Aes128(Box::new(c))),
            };
            if let Some(plain) = gcm.and_then(|g| g.open(nonce, ciphertext)) {
                opened = Some(plain);
                break;
            }
        }

        let plain =
            opened.ok_or_else(|| Error::Decrypt("密钥环上没有一把钥匙能解开这段密文".into()))?;

        Value::decode(&plain)
    }

    /// 解密并断言结果是字符串。
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
