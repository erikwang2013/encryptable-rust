// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 可选集成：把任意 `Serialize` 类型当 JSON 存进加密列。
//!
//! 只在 `serde` feature 打开时编译，默认构建不碰它。
//!
//! 做的是「序列化成 JSON 字符串 → 塞进类型信封 → 加密」以及反过来。JSON 因此
//! 躺在**认证过的密文之内**，不需要为它单独设计一套二进制信封。

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::encrypter::AeadEncrypter;
use crate::error::{Error, Result};
use crate::serializer::Value;

impl AeadEncrypter {
    /// 把任意可序列化的值转成 JSON 再加密。
    ///
    /// ```
    /// # #[cfg(feature = "serde")] {
    /// use encryptable::config::ArrayConfig;
    /// use encryptable::AeadEncrypter;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize, PartialEq, Debug)]
    /// struct Patient { name: String, age: u8 }
    ///
    /// let encrypter = AeadEncrypter::new(&ArrayConfig::new(
    ///     "0123456789abcdef0123456789abcdef",
    /// ))?;
    ///
    /// let p = Patient { name: "张三".into(), age: 42 };
    /// let ciphertext = encrypter.encrypt_json(&p)?;
    /// assert_eq!(encrypter.decrypt_json::<Patient>(&ciphertext)?, p);
    /// # }
    /// # Ok::<(), encryptable::Error>(())
    /// ```
    // `?Sized` 是为了让 `encrypt_json("字符串字面量")` 这类调用成立 ——
    // 传进来的是 `&str`，若要求 `T: Sized` 就得先 `&"…".to_string()`。
    pub fn encrypt_json<T: Serialize + ?Sized>(&self, value: &T) -> Result<String> {
        let json = serde_json::to_string(value)
            .map_err(|e| Error::Serialize(format!("转 JSON 失败：{e}")))?;
        self.seal(Value::String(json))
    }

    /// 解密并还原成 `T`。
    pub fn decrypt_json<T: DeserializeOwned>(&self, payload: &str) -> Result<T> {
        let json = self.decrypt_text(payload)?;
        serde_json::from_str(&json)
            .map_err(|e| Error::Unserialize(format!("从 JSON 还原失败：{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ArrayConfig;
    use serde::{Deserialize, Serialize};

    const K1: &str = "0123456789abcdef0123456789abcdef";

    fn enc() -> AeadEncrypter {
        AeadEncrypter::new(&ArrayConfig::new(K1)).unwrap()
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Record {
        name: String,
        age: u8,
        tags: Vec<String>,
        opt: Option<i32>,
    }

    #[test]
    fn structs_round_trip() {
        let e = enc();
        let r = Record {
            name: "张三".into(),
            age: 42,
            tags: vec!["a".into(), "b".into()],
            opt: None,
        };
        let c = e.encrypt_json(&r).unwrap();
        assert_eq!(e.decrypt_json::<Record>(&c).unwrap(), r);
    }

    #[test]
    fn plain_scalars_round_trip() {
        let e = enc();
        let c = e.encrypt_json(&42i64).unwrap();
        assert_eq!(e.decrypt_json::<i64>(&c).unwrap(), 42);

        let c = e.encrypt_json("文字").unwrap();
        assert_eq!(e.decrypt_json::<String>(&c).unwrap(), "文字");

        let c = e.encrypt_json(&vec![1, 2, 3]).unwrap();
        assert_eq!(e.decrypt_json::<Vec<i32>>(&c).unwrap(), vec![1, 2, 3]);
    }

    /// JSON 躺在密文里面，所以外面看不到任何结构。
    #[test]
    fn json_is_not_visible_in_the_ciphertext() {
        let e = enc();
        let c = e
            .encrypt_json(&Record {
                name: "秘密姓名".into(),
                age: 1,
                tags: vec![],
                opt: Some(1),
            })
            .unwrap();
        assert!(!c.contains("秘密姓名"));
        assert!(!c.contains("name"));
    }

    #[test]
    fn type_mismatch_is_an_error_not_garbage() {
        let e = enc();
        let c = e
            .encrypt_json(&Record {
                name: "x".into(),
                age: 1,
                tags: vec![],
                opt: None,
            })
            .unwrap();
        assert!(matches!(
            e.decrypt_json::<Vec<i32>>(&c),
            Err(Error::Unserialize(_))
        ));
    }

    #[test]
    fn wrong_key_cannot_read_json() {
        let e = enc();
        let c = e.encrypt_json(&"secret").unwrap();
        let other =
            AeadEncrypter::new(&ArrayConfig::new("fedcba9876543210fedcba9876543210")).unwrap();
        assert!(other.decrypt_json::<String>(&c).is_err());
    }
}
