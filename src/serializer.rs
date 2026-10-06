// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 类型信封：把值的类型一起加密进去，解密时才知道该还原成什么。
//!
//! PHP 版用的是文本信封（`string:foo` / `integer:5`），还原时走 `settype()`，
//! 于是 `integer:"abc"` 会**静默变成** `0`。这里换成紧凑二进制：一个类型字节
//! 加定长载荷，类型对不上就报错，不猜。
//!
//! ```text
//! tag(1B) 载荷
//! 0x00    （无）               Null
//! 0x01    UTF-8 字节           String
//! 0x02    i64 小端 8 字节      Int
//! 0x03    f64 小端 8 字节      Float
//! 0x04    1 字节 0/1           Bool
//! ```

use crate::error::{Error, Result};

/// 信封里的类型字节。
mod tag {
    pub const NULL: u8 = 0x00;
    pub const STRING: u8 = 0x01;
    pub const INT: u8 = 0x02;
    pub const FLOAT: u8 = 0x03;
    pub const BOOL: u8 = 0x04;
}

/// 可以进类型信封的值。
///
/// 只覆盖 PHP 版支持的同一组标量 —— 数组与结构体必须先由调用方自己编码
/// （JSON、bincode 等）再当字符串放进来，而不是让信封去猜。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// 空值。注意：`Value::Null` 与「没有值」不同 —— 前者会被加密成密文。
    Null,
    /// 字符串。
    String(String),
    /// 64 位有符号整数。
    Int(i64),
    /// 64 位浮点数。
    Float(f64),
    /// 布尔。
    Bool(bool),
}

impl Value {
    /// 该值的信封类型名，给错误信息与诊断用。
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::String(_) => "string",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Bool(_) => "bool",
        }
    }

    /// 编码成 `tag || payload`。
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Null => vec![tag::NULL],
            Self::String(s) => {
                let mut out = Vec::with_capacity(1 + s.len());
                out.push(tag::STRING);
                out.extend_from_slice(s.as_bytes());
                out
            }
            Self::Int(i) => {
                let mut out = Vec::with_capacity(9);
                out.push(tag::INT);
                out.extend_from_slice(&i.to_le_bytes());
                out
            }
            Self::Float(v) => {
                let mut out = Vec::with_capacity(9);
                out.push(tag::FLOAT);
                out.extend_from_slice(&v.to_le_bytes());
                out
            }
            Self::Bool(b) => vec![tag::BOOL, u8::from(*b)],
        }
    }

    /// 从 `tag || payload` 解出值。
    ///
    /// 载荷长度必须与类型字节**严格**吻合：多一个字节也报错。放着不管的话，
    /// 未来版本往载荷尾部加字段时，老代码会把新体当旧体静默读掉。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (first, rest) = bytes
            .split_first()
            .ok_or_else(|| Error::Unserialize("载荷为空，连类型字节都没有".into()))?;

        match *first {
            tag::NULL => {
                if !rest.is_empty() {
                    return Err(Error::Unserialize(format!(
                        "null 类型不应有载荷，却多出 {} 字节",
                        rest.len()
                    )));
                }
                Ok(Self::Null)
            }
            tag::STRING => {
                let s = std::str::from_utf8(rest)
                    .map_err(|e| Error::Unserialize(format!("字符串不是合法 UTF-8：{e}")))?;
                Ok(Self::String(s.to_owned()))
            }
            tag::INT => {
                let raw: [u8; 8] = rest.try_into().map_err(|_| {
                    Error::Unserialize(format!("int 载荷应为 8 字节，实际 {} 字节", rest.len()))
                })?;
                Ok(Self::Int(i64::from_le_bytes(raw)))
            }
            tag::FLOAT => {
                let raw: [u8; 8] = rest.try_into().map_err(|_| {
                    Error::Unserialize(format!("float 载荷应为 8 字节，实际 {} 字节", rest.len()))
                })?;
                Ok(Self::Float(f64::from_le_bytes(raw)))
            }
            tag::BOOL => match rest {
                [0] => Ok(Self::Bool(false)),
                [1] => Ok(Self::Bool(true)),
                other => Err(Error::Unserialize(format!(
                    "bool 载荷应为单个 0 或 1，实际 {other:?}"
                ))),
            },
            other => Err(Error::Unserialize(format!("陌生的类型字节 0x{other:02x}"))),
        }
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

/// `None` 映射到 [`Value::Null`]，`Some` 内层照常。
///
/// 之所以不做「`None` 就跳过加密」：那会把两种不同的「空」压成一种 ——
/// 「字段明确为空」应当落一段加密过的 [`Value::Null`]，而「字段压根没设置」
/// 才该落 SQL NULL。要不要加密由调用方决定，两者不会自己混起来：
///
/// ```
/// # use encryptable::{AeadEncrypter, Value};
/// # use encryptable::config::ArrayConfig;
/// # let encrypter = AeadEncrypter::new(&ArrayConfig::new("0123456789abcdef0123456789abcdef"))?;
/// // 明确为空 → 加密后的 Null（列里是密文）
/// let sealed = encrypter.encrypt(Value::from(None::<String>))?;
/// assert_eq!(encrypter.decrypt(&sealed)?, Value::Null);
///
/// // 没设置 → 压根不调加密，列里是 SQL NULL
/// let skipped: Option<String> = None;
/// assert!(skipped.is_none());
/// # Ok::<(), encryptable::Error>(())
/// ```
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Self::Null, Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: Value) {
        let encoded = v.encode();
        let decoded = Value::decode(&encoded).expect("应当解得出");
        assert_eq!(v, decoded, "{v:?} 往返不一致");
    }

    #[test]
    fn scalars_round_trip() {
        round_trip(Value::Null);
        round_trip(Value::String(String::new()));
        round_trip(Value::String("hello 世界".into()));
        round_trip(Value::Int(0));
        round_trip(Value::Int(i64::MIN));
        round_trip(Value::Int(i64::MAX));
        round_trip(Value::Float(0.0));
        round_trip(Value::Float(-1.5));
        round_trip(Value::Bool(true));
        round_trip(Value::Bool(false));
    }

    #[test]
    fn from_impls_land_on_the_right_variant() {
        assert_eq!(Value::from("a"), Value::String("a".into()));
        assert_eq!(Value::from(5i32), Value::Int(5));
        assert_eq!(Value::from(5i64), Value::Int(5));
        assert_eq!(Value::from(1.25f64), Value::Float(1.25));
        assert_eq!(Value::from(true), Value::Bool(true));
        assert_eq!(Value::from(None::<i64>), Value::Null);
        assert_eq!(Value::from(Some(7i64)), Value::Int(7));
    }

    /// 这正是 PHP 版的缺陷：`integer:"abc"` 静默变 0。这里必须报错。
    #[test]
    fn type_confusion_is_an_error_not_a_coercion() {
        let mut bad = vec![tag::INT];
        bad.extend_from_slice(b"abc");
        assert!(matches!(Value::decode(&bad), Err(Error::Unserialize(_))));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert!(matches!(
            Value::decode(&[tag::NULL, 0x00]),
            Err(Error::Unserialize(_))
        ));
        assert!(matches!(
            Value::decode(&[tag::BOOL, 1, 0]),
            Err(Error::Unserialize(_))
        ));
        // 9 字节的 int 多了一字节
        let mut long = vec![tag::INT];
        long.extend_from_slice(&[0u8; 9]);
        assert!(matches!(Value::decode(&long), Err(Error::Unserialize(_))));
    }

    #[test]
    fn empty_and_unknown_payloads_are_rejected() {
        assert!(matches!(Value::decode(&[]), Err(Error::Unserialize(_))));
        assert!(matches!(Value::decode(&[0x7f]), Err(Error::Unserialize(_))));
    }

    #[test]
    fn bool_only_accepts_zero_or_one() {
        assert_eq!(Value::decode(&[tag::BOOL, 0]).unwrap(), Value::Bool(false));
        assert_eq!(Value::decode(&[tag::BOOL, 1]).unwrap(), Value::Bool(true));
        assert!(matches!(
            Value::decode(&[tag::BOOL, 2]),
            Err(Error::Unserialize(_))
        ));
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        assert!(matches!(
            Value::decode(&[tag::STRING, 0xff, 0xfe]),
            Err(Error::Unserialize(_))
        ));
    }
}
