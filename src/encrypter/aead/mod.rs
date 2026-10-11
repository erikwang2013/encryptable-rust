// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 应用侧加密：随机 nonce 的 AEAD 信封。
//!
//! ```text
//! 载荷 = base64( 版本(1B) || nonce(12B) || AES-GCM 密文 || tag(16B) )
//! 明文 = 类型信封( tag(1B) || 载荷 )        见 crate::serializer
//! AAD  = 版本字节 [‖ 上下文]                上下文见 seal_with_context
//! ```
//!
//! # 版本字节
//!
//! - `0x03`（当前，写用）：密钥是主密钥经 HKDF 派生的**应用侧子密钥**。子密钥的
//!   理由见 crate 文档「两条路径」一节：DB 侧的确定性 ECB 是一条 `E_K(·)` 加密
//!   预言机，主密钥绝不能与它共用。
//! - `0x01`（旧格式，只读）：1.2.x 写出，主密钥直接加密。照旧解得开；
//!   用 [`AeadEncrypter::rotate_to_current_key`] 搬到 `0x03` 之后即可退役。
//!
//! # 信封设计的三个「不做」
//!
//! - **不做手工 HMAC**：GCM 的 tag 本身就是认证，再叠一层 HMAC 只是把同一件事做两遍。
//! - **不做明文标记判据**：以明文前缀判断「密钥对不对」既证明不了任何事（真正的判据
//!   是认证能否通过），又把明文痕迹混进密文列 —— GCM 的 tag 校验失败就是密钥不对或
//!   密文被改，由密码学保证，不靠约定。
//! - **不做非 AEAD 分支**：CBC/ECB 在这条路径上不支持。没有认证的密文会在解密时
//!   静默产出垃圾，这条路径只收 AEAD。

use aes_gcm::aead::{Aead, AeadCore, OsRng, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::cipher::Cipher;
use crate::config::EncryptableConfig;
use crate::error::{Error, Result};
use crate::key::{Key, KeyRing};
use crate::serializer::Value;

/// 应用侧载荷当前写出的格式字节。DB 侧是 [`0x04`](crate::encrypter::DbEncrypter::VERSION)，
/// 两者不可互换。
pub const VERSION: u8 = 0x03;

/// 应用侧载荷的旧格式字节（1.2.x，主密钥直用）。**只读** —— 新密文不会再用它。
pub const LEGACY_VERSION: u8 = 0x01;

/// GCM nonce 长度，RFC 5116 推荐值。
const NONCE_LEN: usize = 12;

/// GCM tag 长度。
const TAG_LEN: usize = 16;

/// 载荷最小长度：版本 + nonce + tag（空明文）。
const MIN_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

/// 真载荷 base64 后的最短字符数：`ceil(MIN_LEN / 3) × 4`（29 字节 ⇒ 40 字符）。
///
/// 形状判定与 DB 侧的误拒闸门都靠它 —— 短于它的输入不可能解码出 `MIN_LEN`
/// 字节，连 base64 都不用试。
pub(crate) const MIN_B64_LEN: usize = MIN_LEN.div_ceil(3) * 4;

/// 应用侧加密器。
///
/// 配置在构造时就被解析成一串密钥，之后不再读环境、不再解析字符串。
///
/// 密钥环上**每一把钥匙都建两把 cipher**（旧格式的主密钥原样 + 当前格式的
/// HKDF 子密钥），全部在构造时一次建好：AES 的密钥调度是每次解密都要付的
/// 固定开销，放在解密循环里重建等于每请求重算一遍。
#[derive(Clone)]
pub struct AeadEncrypter {
    /// 与 `ring` 索引对齐。`slots[0]` 即主密钥槽，加密只用它。
    slots: Vec<Slot>,
    ring: KeyRing,
    /// 密码名，构造时定下来（原本靠 match `cipher` 字段推，现在直接存）。
    name: &'static str,
}

/// 环上一个位置的两把 cipher：旧格式用主密钥原样，当前格式用派生出的子密钥。
#[derive(Clone)]
struct Slot {
    /// 读 `0x01`（1.2.x）载荷用。
    legacy: GcmCipher,
    /// 读写 `0x03` 载荷用。
    derived: GcmCipher,
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

    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
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
    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
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

        // 环上**每一个位置**都建两把 cipher，而不是只建主密钥那两把。
        //
        // 旧格式（0x01）用主密钥原样解密；当前格式（0x03）用 HKDF 子密钥。子密钥
        // 由每把钥匙各自派生 —— 轮换时一把旧钥匙（现在是 previous_keys 里的某一
        // 把）当年写出的 0x03 数据，今天仍然解得开。
        //
        // 密钥调度（外加派生的 HKDF 展开）是固定开销，一次性付掉即可：
        // 放在解密循环里重建等于每请求白算一遍（v1.2.1 修的就是这个）。
        let mut slots = Vec::with_capacity(ring.len());
        for key in ring.iter() {
            let derived =
                crate::support::subkeys::derive(key, crate::support::subkeys::AEAD_INFO, cipher)?;
            slots.push(Slot {
                legacy: GcmCipher::new(cipher, key.as_bytes())?,
                derived: GcmCipher::new(cipher, derived.as_bytes())?,
            });
        }

        Ok(Self {
            slots,
            ring,
            name: cipher.as_str(),
        })
    }

    /// 使用的密码名。
    pub fn cipher_name(&self) -> &'static str {
        self.name
    }

    /// 主密钥的槽。加密只用它。
    ///
    /// 不变量：`KeyRing::new` 保证环上至少有一把钥匙，而 `slots` 与环等长，
    /// 所以下标 0 必然存在。
    fn primary_slot(&self) -> &Slot {
        &self.slots[0]
    }

    /// 环上钥匙数量（含主密钥）。
    pub fn ring_len(&self) -> usize {
        self.ring.len()
    }

    /// 加密一个值。
    ///
    /// 已经是本格式（任何一代）的密文则**原样返回**，不会二次加密。判定方式是
    /// 试着解开它 —— 光看形状会把「base64 解出来首字节恰好是 0x03 的明文」误判
    /// 成密文直接存库，从此解不开；两阶段判定专治这个假阳性。
    ///
    /// 注意：**绑定上下文**的密文（[`seal_with_context`](Self::seal_with_context)）
    /// 别往这里喂 —— 它认证不上，会被当作普通明文再加密一遍。要回灌请走
    /// [`seal_with_context`](Self::seal_with_context) 对应的一次性写入路径。
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
        //    解出来首字节恰好是格式字节的明文会被误判成密文然后直接存库，从此
        //    解不开；第二阶段专治这个假阳性。
        if let Value::String(ref s) = value
            && self.is_encrypted(s)
            && self.decrypt(s).is_ok()
        {
            return Ok(s.clone());
        }

        self.seal(value)
    }

    /// 无条件加密，不做「是否已是密文」的判定，也不绑定上下文。
    ///
    /// 只在明确知道输入是明文时用。重复加密同一段明文是完全合法的 ——
    /// nonce 随机会让两次结果不同。
    ///
    /// # Errors
    ///
    /// 底层 AEAD 加密失败时返回 [`Error::Encrypt`]（明文超长等）。不会因为输入
    /// 看起来像密文而失败。
    pub fn seal(&self, value: impl Into<Value>) -> Result<String> {
        self.seal_with_context("", value)
    }

    /// 绑定上下文加密。
    ///
    /// 上下文进 AAD —— 解密时 AAD 对不上，认证就失败。用于把一段密文钉死在
    /// 「它属于哪一行/哪一列」上，防「把别人的密文粘到自己行上」这类移植：
    ///
    /// ```
    /// # use encryptable::{AeadEncrypter, Value};
    /// # use encryptable::config::ArrayConfig;
    /// # let encrypter = AeadEncrypter::new(&ArrayConfig::new("0123456789abcdef0123456789abcdef"))?;
    /// let sealed = encrypter.seal_with_context("users/42.phone", "13800138000")?;
    /// assert_eq!(
    ///     encrypter.decrypt_text_with_context("users/42.phone", &sealed)?,
    ///     "13800138000"
    /// );
    /// // 换一个上下文（哪怕只是换了行号）就认证不上
    /// assert!(encrypter.decrypt_with_context("users/43.phone", &sealed).is_err());
    /// # Ok::<(), encryptable::Error>(())
    /// ```
    ///
    /// 空上下文与 [`seal`](Self::seal) 完全等价（AAD 都是 `[0x03]`）。
    /// 载荷仍是 `0x03` 格式，[`decrypt`](Self::decrypt)（不带上下文）**解不开**
    /// 绑定过的密文 —— 这是特性，不是缺陷。
    ///
    /// # Errors
    ///
    /// 与 [`seal`](Self::seal) 相同。
    pub fn seal_with_context(&self, context: &str, value: impl Into<Value>) -> Result<String> {
        let plaintext = Zeroizing::new(value.into().encode());

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // 空上下文走无分配的常量路径 —— 那是绝大多数调用。
        let ctx = context.as_bytes();
        let ciphertext = if ctx.is_empty() {
            self.primary_slot()
                .derived
                .seal(&nonce, &[VERSION], &plaintext)?
        } else {
            let mut aad = Vec::with_capacity(1 + ctx.len());
            aad.push(VERSION);
            aad.extend_from_slice(ctx);
            self.primary_slot().derived.seal(&nonce, &aad, &plaintext)?
        };

        let mut payload = Vec::with_capacity(MIN_LEN + ciphertext.len());
        payload.push(VERSION);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(&payload))
    }

    /// 形状检查 + 长度下限：解出完整载荷，交给调用方按字节 0 分派。
    ///
    /// 先看格式字节再看长度：格式字节是更具体的诊断。反过来做的话，
    /// 一段短的 DB 侧载荷会被报成「太短」，而真正的原因是走错了加密器。
    fn decode_checked(payload: &str) -> Result<Vec<u8>> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|e| Error::Base64(e.to_string()))?;

        match decoded.first() {
            Some(&VERSION) | Some(&LEGACY_VERSION) => {}
            Some(&found)
                if found == crate::encrypter::DbEncrypter::VERSION
                    || found == crate::encrypter::DbEncrypter::LEGACY_VERSION =>
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
        }

        if decoded.len() < MIN_LEN {
            return Err(Error::Decrypt(format!(
                "载荷只有 {} 字节，短于最小的 {MIN_LEN} 字节",
                decoded.len()
            )));
        }

        Ok(decoded)
    }

    /// 试解的收尾：解不开一律一句「环上没有一把钥匙能解开」。
    ///
    /// 刻意不区分「是哪一把解开的」，也不区分「认证失败 / 上下文不匹配」——
    /// 把「第几把」泄出去等于泄了轮换进度。
    fn finish(opened: Option<Zeroizing<Vec<u8>>>) -> Result<Value> {
        let plain =
            opened.ok_or_else(|| Error::Decrypt("密钥环上没有一把钥匙能解开这段密文".into()))?;
        Value::decode(&plain)
    }

    /// 解密（未绑定上下文）。密钥环上任意一把钥匙成功即可。
    ///
    /// 旧格式（`0x01`）与当前格式（`0x03`，未绑定）都认。失败一律返回
    /// [`Error::Decrypt`] —— **不做「失败就返回原文」的宽松回退**。
    /// 那种回退是明文被悄悄写进数据库的主要途径：加密列里躺着的明文看起来
    /// 和密文一模一样，直到某天有人审计。确实需要的话用
    /// [`decrypt_or_original`](Self::decrypt_or_original)，让这个决定显式出现在调用点。
    ///
    /// # Errors
    ///
    /// - [`Error::Base64`] —— 载荷不是合法 base64
    /// - [`Error::WrongFormat`] —— 载荷是 **DB 侧**密文，走错了加密器
    /// - [`Error::Decrypt`] —— 版本字节陌生、长度不足、上下文绑定不匹配，
    ///   或密钥环上没有一把钥匙能解开
    /// - [`Error::Unserialize`] —— 解出来了，但类型信封读不出（类型字节陌生、载荷长度不符）
    pub fn decrypt(&self, payload: &str) -> Result<Value> {
        let decoded = Self::decode_checked(payload)?;
        let version = decoded[0];
        let nonce = &decoded[1..1 + NONCE_LEN];
        let ciphertext = &decoded[1 + NONCE_LEN..];

        // 逐把钥匙试，cipher 在构造时就按环建好了，这里只剩一次 AEAD 解封。
        let mut opened = None;
        for slot in &self.slots {
            let got = match version {
                LEGACY_VERSION => slot.legacy.open(nonce, &[LEGACY_VERSION], ciphertext),
                _ => slot.derived.open(nonce, &[VERSION], ciphertext),
            };
            if let Some(plain) = got {
                opened = Some(Zeroizing::new(plain));
                break;
            }
        }

        Self::finish(opened)
    }

    /// 解密一个**绑定了上下文**的当前格式载荷。
    ///
    /// 只认与 `context` 完全一致的 AAD；旧格式（`0x01`）没有上下文可言，
    /// 这里一律拒绝 —— 请用 [`decrypt`](Self::decrypt)。
    ///
    /// # Errors
    ///
    /// 与 [`decrypt`](Self::decrypt) 相同，另加：载荷是 `0x01` 旧格式。
    pub fn decrypt_with_context(&self, context: &str, payload: &str) -> Result<Value> {
        let decoded = Self::decode_checked(payload)?;
        let version = decoded[0];
        if version != VERSION {
            return Err(Error::Decrypt(
                "0x01 是旧格式，没有上下文绑定；请用 decrypt()".into(),
            ));
        }
        let nonce = &decoded[1..1 + NONCE_LEN];
        let ciphertext = &decoded[1 + NONCE_LEN..];

        let ctx = context.as_bytes();
        let mut opened = None;
        for slot in &self.slots {
            let got = if ctx.is_empty() {
                slot.derived.open(nonce, &[VERSION], ciphertext)
            } else {
                let mut aad = Vec::with_capacity(1 + ctx.len());
                aad.push(VERSION);
                aad.extend_from_slice(ctx);
                slot.derived.open(nonce, &aad, ciphertext)
            };
            if let Some(plain) = got {
                opened = Some(Zeroizing::new(plain));
                break;
            }
        }

        Self::finish(opened)
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

    /// 带上下文的 [`decrypt_text`](Self::decrypt_text)。
    ///
    /// # Errors
    ///
    /// 与 [`decrypt_with_context`](Self::decrypt_with_context) 相同，另加：
    /// 解开但值不是字符串。
    pub fn decrypt_text_with_context(&self, context: &str, payload: &str) -> Result<String> {
        match self.decrypt_with_context(context, payload)? {
            Value::String(s) => Ok(s),
            other => Err(Error::Decrypt(format!(
                "期望字符串，实际是 {}",
                other.type_name()
            ))),
        }
    }

    /// 宽松解密：解不开就原样返回输入。
    ///
    /// 默认路径是「失败不静默」（解不开就报错），这里把那套纪律放松成**显式选项**：
    /// 只在「这一列是历史遗留的混合列，可能既有密文也有明文」这类迁移场景下用，
    /// 由调用点自己承担「把原文原样读出来」这个决定。
    ///
    /// 解出来但值不是字符串时，返回它的 [`Display`](std::fmt::Display) 渲染
    /// （`Int(42)` → `"42"`，`Null` → 空串）。**曾经这里返回的是类型名**
    /// （`Int(42)` → `"int"`）—— 既不是原值也不是原输入，是静默的数据损坏。
    pub fn decrypt_or_original(&self, payload: &str) -> String {
        match self.decrypt(payload) {
            Ok(Value::String(s)) => s,
            Ok(other) => other.to_string(),
            Err(_) => payload.to_owned(),
        }
    }

    /// 廉价判定：形状上像不像应用侧密文（含旧格式）。
    ///
    /// 只做 base64 解码 + 版本字节 + 长度下限，**不碰密钥、不做认证**。代价是
    /// 会有假阳性：一段 base64 解出来首字节恰好是格式字节的明文会被判为密文。
    /// 概率约 2/256 且还需整体是合法 base64，实践中可以接受；真正需要确定性答案
    /// 的场合请用 [`decrypt`](Self::decrypt)（它会真的认证一次）。
    pub fn is_encrypted(&self, value: &str) -> bool {
        // 长度前置：短于真载荷最短 base64 长度的输入不可能解出 `MIN_LEN` 字节，
        // 连解码都不用试（base64 的 decode 实现是先分配再校验长度）。
        // 判据是必要条件，不会漏判任何真密文。
        if value.len() < MIN_B64_LEN || !value.len().is_multiple_of(4) {
            return false;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
            return false;
        };
        decoded.len() >= MIN_LEN && matches!(decoded[0], VERSION | LEGACY_VERSION)
    }

    /// 用环上任意钥匙解出明文，再用当前主密钥重新加密。
    ///
    /// 轮换的第三步：新数据已经用新主密钥写入，这个方法把存量数据一把一把搬过去
    /// （旧格式 `0x01` 同时被搬成 `0x03`）。输入本来就是明文时原样返回，方便在
    /// 批处理里无脑调用。
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

    /// 带上下文的轮换：读绑定 `context` 的密文，写回仍绑定 `context` 的密文。
    ///
    /// # Errors
    ///
    /// 与 [`rotate_to_current_key`](Self::rotate_to_current_key) 相同，
    /// 只是试解走 [`decrypt_with_context`](Self::decrypt_with_context)。
    pub fn rotate_to_current_key_with_context(
        &self,
        context: &str,
        payload: &str,
    ) -> Result<String> {
        if !self.is_encrypted(payload) {
            return Ok(payload.to_owned());
        }
        let value = self.decrypt_with_context(context, payload)?;
        self.seal_with_context(context, value)
    }

    /// 主密钥的十六进制表示，给需要核对配置的场景用。
    ///
    /// 返回的是**主密钥**（与配置里的密钥等价），不是派生的子密钥 ——
    /// 手工写 DB 侧 SQL 片段请用
    /// [`DbEncrypter::derived_key_hex`](crate::encrypter::DbEncrypter::derived_key_hex)。
    pub fn primary_key_hex(&self) -> Zeroizing<String> {
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
