<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# encryptable-rust

<img src="../../pet.svg" alt="Locky · 小锁灵 — the project pet" width="26"> [简体中文](../../../README.md) · **English (this page)**

Query-friendly anonymization / encryption for sensitive columns: encrypt before persisting, decrypt on read, and emit MySQL / PostgreSQL-compatible SQL fragments for comparing against encrypted columns. A Rust port of the PHP package [`erikwang2013/encryptable`](https://github.com/erikwang2013/encryptable), it uses two paths to split apart the pair of requirements that usually cannot both be met — "encrypt at rest" and "query by original value": the application side AES-256-GCM (random nonce, authenticated, **the default choice**), the DB side AES-256-ECB (deterministic, reserved for columns that must be matched by original value inside a `WHERE`).

Project pet **Locky · 小锁灵** ([`docs/pet.svg`](../../pet.svg)) — the amber one on the key ring is the current primary key; the two grey ones are `previous_keys`.

Framework integrations cover **axum · actix-web · rocket · poem · salvo · warp · [bee-rust](https://github.com/erikwang2013/bee-rust) · [e-cat](https://github.com/erikwang2013/e-cat)**, all opt-in; a default build pulls in none of them.

---

## Project pet: Locky · 小锁灵

<img src="../../pet.svg" alt="Locky · 小锁灵 — the encryptable-rust project pet" width="340">

A lock spirit wearing a key ring. The persona is not decoration — it draws this library's key model:

| Depiction | What it maps to |
|-----------|-----------------|
| The amber key centred on the ring | **The current primary key**. Every new ciphertext is produced with it (`KeyRing::primary()`) |
| The two grey keys (each turned out 30°) | `previous_keys` — still on the ring, still able to open old ciphertexts, until you retire them |
| The key ring itself | `KeyRing`: primary first, retired keys after; on decryption it tries them in order, and any one succeeding is enough |
| The AEAD badge on the clasp | The application side's AES-GCM authentication tag: if it will not open, either the key is wrong or the ciphertext was altered — there is no third explanation |
| The nameplate `Locky · 小锁灵` | The pet's name (`pet::NAME`) |

Motto: **as long as the key is still on the ring, the old ciphertext still opens.**

The artwork is baked into the library with `include_str!` ([`src/pet.rs`](../../../src/pet.rs) — zero runtime cost, not linked unless used); print `pet::ASCII` straight to a terminal or a log:

```rust
use encryptable::pet;

println!("{}", pet::ASCII);

//          .--.
//         /    \        Locky · 小锁灵
//        _|    |_
//       |        |      amber key = primary key
//       |  o  o  |      two grey keys = previous_keys
//       |    ^   |      the clasp = AEAD tag
//       |________|
```

The artwork is a first-class part of the crate, not a documentation attachment. Four constants and four functions are public, shared by the README, the CLI banner and any downstream admin UI:

| API | Returns | For |
|-----|---------|-----|
| `pet::NAME` / `pet::TAGLINE` | name and motto | UI copy |
| `pet::ASCII` / `pet::ascii()` | monospace rendition | terminals, logs, CLI banner |
| `pet::SVG` / `pet::svg()` | raw SVG markup | README, admin back office |
| `pet::data_uri()` | `data:image/svg+xml;base64,…` | drop straight into an HTML `<img src>` |
| `pet::SVG_LEN` | byte length | when you need to size a buffer |

`data_uri()` is the one meant for downstream use: it is the same `include_str!` result as `SVG`, so callers **do not have to depend on this library's file layout** — the artwork is guaranteed to be in the binary. Serving an icon endpoint:

```rust
use axum::response::Html;

async fn pet_icon() -> Html<String> {
    Html(format!(
        r#"<img src="{}" alt="Locky" width="64">"#,
        encryptable::pet::data_uri()
    ))
}
```

It is on the command line too: `encryptable pet` prints the artwork, and both `encryptable --version` and `--help` carry it. CLI errors also carry the pet, **but only on an interactive terminal** — scripted and CI runs that redirect stderr into a log do not suddenly get seven lines of ASCII.

#### Built-in icon endpoints

Every framework adapter ships a ready-made handler: mount it and you have the project icon at `Content-Type: image/svg+xml`, with nothing to write yourself.

```rust
// axum (bee-rust and e-cat use this one too — both sit on axum)
Router::new().route("/pet.svg", get(encryptable::integrations::axum::pet))

// actix-web
App::new().route("/pet.svg", web::get().to(encryptable::integrations::actix::pet))

// rocket
rocket::build().mount("/", routes![encryptable::integrations::rocket::pet])

// poem
Route::new().at("/pet.svg", get(encryptable::integrations::poem::pet))

// salvo
Router::new().get(encryptable::integrations::salvo::pet)

// warp
encryptable::integrations::warp::pet()      // the /pet.svg path is already bound
```

salvo additionally has `write_pet(&mut Response)`, which does not depend on its handler machinery — anything holding a `&mut Response` can use it.

`Content-Type` is the one thing this endpoint is easy to get wrong: without it the browser renders the SVG as plain text and the user sees a screenful of XML instead of the padlock with the key ring — so every adapter's test pins that header.

`docs/pet.svg` **must not** go into Cargo's `exclude` — `include_str!` reads it at compile time, and excluding it fails the build on the spot (`cargo package` errors out outright rather than silently shipping without it).

---

## Project layout

```
encryptable-rust/
├── src/
│   ├── lib.rs                 crate docs, module exports, the two-path comparison table
│   ├── cipher.rs              cipher allowlist (6) and three properties: is_aead / is_deterministic / key_len
│   ├── key.rs                 Key (zeroize + length check + redacted Debug) and KeyRing (primary + retired keys)
│   ├── serializer.rs          type envelope Value: tag(1B) || payload
│   ├── error.rs               the Error enum (13 variants) and Result
│   ├── pet.rs                 project pet artwork (NAME · TAGLINE · ASCII · SVG + svg()/ascii()/data_uri())
│   ├── guard.rs               request guard Guard: the encryption handle shared across requests (Arc-shared, Send+Sync)
│   ├── serde_support.rs       optional integration: encrypt_json / decrypt_json (--features serde)
│   ├── config/                EncryptableConfig trait + DbDriver dialects
│   │                          ArrayConfig (config in code) / EnvConfig (reads ENCRYPTION_*)
│   ├── encrypter/             exports of the two paths + format-byte invariants
│   │   ├── aead/mod.rs        application-side envelope · key ring · rotation
│   │   ├── aead/tests.rs      application-side unit tests (split off to stay under the 500-line-per-file cap)
│   │   ├── db/mod.rs          PKCS#7 + ECB · SQL fragments · column-name allowlist
│   │   └── db/tests.rs        DB-side unit tests (including the OpenSSL golden vector)
│   ├── integrations/          framework adapter layer: Guarded trait + one module per framework
│   │                          mod.rs (Guarded · GuardNotConfigured), axum.rs,
│   │                          actix.rs, rocket.rs, poem.rs, salvo.rs, warp.rs,
│   │                          ecat.rs (tower layer); bee_rust reuses axum
│   ├── support/previous_keys.rs  comma-separated retired-key parsing (a JSON array is explicitly rejected)
│   └── bin/encryptable.rs     CLI: 8 commands, hand-written argument parsing, no clap
├── tests/
│   ├── db_sql.rs              SQL fragments pinned character by character, column-name injection defences, stability of bound queries
│   ├── invariants.rs          cross-module invariants: round trip, tampering, determinism, the two payload kinds never working with each other
│   └── rotation.rs            the entire zero-downtime rotation migration path
├── examples/quickstart.rs     runnable demo of both paths + one complete rotation
├── docs/
│   ├── pet.svg                project pet (inlined by src/pet.rs via include_str!, keep it out of exclude)
│   ├── diagrams/zh-CN/        Chinese diagrams: architecture · features · request-lifecycle · lifecycle
│   ├── diagrams/en/           the same diagrams in English
│   ├── i18n/en/README.md      English README
│   ├── social-preview.png     1280×640 social preview card (upload in repo settings; not shipped in the crate)
│   ├── social-preview.svg     its editable source
│   ├── alipay.png             donation QR code
│   └── weixinpay.png          donation QR code
├── .github/workflows/ci.yml   CI: fmt · clippy · test · MSRV 1.88 · one matrix job per feature · packaging
└── Cargo.toml                 default dependencies are only aes-gcm / aes / zeroize / base64
```

---

## Design rationale

### Why "query-friendly encryption"

Encryption at rest (not hashing, not masking) and "query by the original value" usually cannot both be had: authenticated encryption with a random nonce produces a different ciphertext every time, so `WHERE phone = ?` never matches. A pure crypto library makes you write your own persistence layer; an ORM solution locks you into one framework. This library covers both ends with two paths, instead of twisting one path into a compromise:

| | Application side `AeadEncrypter` | DB side `DbEncrypter` |
|---|---|---|
| Cipher | AES-256-GCM (authenticated) | AES-256-ECB (deterministic) |
| Ciphertext | Random nonce; the same plaintext differs twice | Constant for the same plaintext |
| Use | **The default**, for every storage scenario | Columns that must be matched by original value in a `WHERE` |
| Risk | None | Frequency analysis works; low-cardinality columns betray privacy |

The DB path being limited to ECB is not legacy baggage, it is a hard boundary of what databases can do: MySQL's `AES_DECRYPT` and pgcrypto's `decrypt` both accept only ECB/CBC — **no GCM**. If you want the database to decrypt for itself, there is no other choice.

The payloads the two paths produce are **incompatible**; each carries its own format byte (application side `0x01`, DB side `0x02`), and mixing them yields an explicit `Error::WrongFormat` rather than a silent second encryption.

### Architectural principles

- **Each path declares for itself which ciphers it accepts** — the application side takes only AEAD (an unauthenticated ciphertext silently yields garbage when tampered with), the DB side takes only deterministic ECB (otherwise equality queries never match). The check is at **construction time**: misconfigure it and it blows up at startup, not on some request path at three in the morning.
- **Configuration is a trait, not a global table** — `EncryptableConfig` has only four methods (`key` / `cipher` / `previous_keys` / `db_driver`), and the last three have default implementations, so the minimal implementation only needs to override `key()`. `ArrayConfig` and `EnvConfig` are its two implementations; no container, no callbacks, no third-level fallback.
- **Reading the config is a snapshot, not a live view** — the encrypter reads environment variables into its own fields at construction, and changing the environment afterwards does not affect an encrypter already built. That is predictable, and it also sidesteps the race where a value is changed by someone else halfway through being read.
- **Key length is fixed at construction time** — no truncation, no zero-padding. Zero-padding would use a weak passphrase directly as a key (there is no KDF, no salt, no iteration here); truncation would leave a rotation landing on the same prefix key, with ops believing the key was rotated when it was not.
- **Keys are wrapped in `Zeroizing` in memory, and `Debug` is hand-written to redact** — `format!("{key:?}")` prints only the byte count; no stray `dbg!` or error message can leak the primary key.
- **Failures are not silent** — what will not decrypt is an error; there is no "return the original on failure" fallback, which is the main way plaintext gets quietly written into an encrypted column. When you really need it, use `decrypt_or_original` so the decision appears explicitly at the call site.
- **A type mismatch is an error, not a guess** — binary type envelope, an `int` payload must be exactly 8 bytes, one byte more is an error too. The PHP version's `integer:"abc"` silently becomes `0`; here it is `Error::Unserialize`.
- **`#![forbid(unsafe_code)]`** — not a single line of `unsafe` in the whole crate.
- **No dependency for what a few dozen lines can do** — hand-written `Display` instead of `thiserror`; hand-written PKCS#7 + ECB instead of the `ecb` crate; hand-written column-name allowlist instead of `regex`; hand-written CLI argument parsing instead of `clap`.

### Trade-offs

| Decision | Choice | Reason |
|----------|--------|--------|
| ECB vs CBC (DB side) | ECB | Determinism is the precondition for equality queries; CBC's IV differs every time, so `WHERE` never matches and the SQL fragment cannot decrypt it either |
| Determinism vs semantic security | Deterministic only on the DB side | The application side keeps the semantic security of a random nonce; determinism is the entry fee for "query by original value", paid only on the columns that need it |
| Binary envelope vs text envelope | Binary | The PHP version goes through `settype()`, where `integer:"abc"` silently becomes `0`; the binary envelope errors out on a type mismatch |
| GCM tag vs hand-rolled HMAC | GCM tag | PHP prepended a 32-byte HMAC to DB-side ciphertext purely so SQL could strip it with `SUBSTRING(..., 33)`; the DB side never verified it — dropped here, the position goes to the version byte and SQL only needs `SUBSTRING(..., 2)` |
| Hand-written ECB vs the `ecb` crate | Hand-written | `ecb` 0.2 rides cipher 0.5, incompatible with the cipher 0.4 of `aes-gcm` 0.10; pulling it in would drag in a second AES stack |
| Strict decryption vs lenient fallback | Strict | A lenient fallback is the main way plaintext gets quietly written into the store; the lenient version is demoted to an explicit `decrypt_or_original` |
| Key as hex vs as a quoted string | hex | The SQL fragment therefore contains no `'` at all, so a missed escape turning into injection is not a possibility — the fragment holds only three fixed constants: `'UTF8'` / `'base64'` / `'aes-ecb'` |
| Byte-level interop with PHP | Not done | The envelope was redesigned (hand-rolled HMAC removed, the `crypt:` dirty bit removed, the non-AEAD branch removed); existing columns must be migrated by re-encrypting on the application side |
| `ENCRYPTION_PREVIOUS_KEYS` accepting a JSON array | Rejected | PHP takes whatever you give it; splitting `["k1","k2"]` on commas yields two **wrong** keys, and a wrong key fails silently inside the key ring — decryption skips it and keeps trying, and finally reports only "all failed", so nobody can tell the real cause was the config format. Better to blow up while reading the config |

---

## Architecture

![Architecture: handler → framework integration layer → request guard → two encryption paths → support modules → database](../../diagrams/en/architecture.svg)

Both ends share one configuration (the `ArrayConfig` / `EnvConfig` implementations of `EncryptableConfig`); the configuration is parsed into the encrypter at **construction time**, after which it no longer reads the environment or parses strings. For each module's responsibilities, see the tree comments in "Project layout".

Read the diagram bottom-up: the support modules (key ring, type envelope, cipher allowlist, configuration, errors) are shared by both encryption paths; each path has its own format byte, and the partition between them is deliberate — feeding one side's ciphertext to the other yields an explicit `Error::WrongFormat`, not a silent second encryption. The framework integration layer is only a thin layer at the very top; its entire job is to put the `Guard` into the handler's hands.

### Payload format

This is the one table worth remembering above all:

| | Layout | Type envelope | AAD |
|---|---|---|---|
| Application side | `base64( 0x01 \|\| nonce(12B) \|\| AES-GCM ciphertext \|\| tag(16B) )` | Yes: `tag(1B) \|\| payload` | Version byte |
| DB side | `base64( 0x02 \|\| AES-ECB-PKCS7(plaintext) )` | **No** | None |

The type envelope's byte definition (application side): a 1-byte tag plus a fixed-length payload — `0x00` no payload (`Null`), `0x01` UTF-8 bytes (`String`), `0x02` little-endian i64 in 8 bytes (`Int`), `0x03` little-endian f64 in 8 bytes (`Float`), `0x04` a single 0/1 byte (`Bool`). Payload length and type byte must match **exactly**; one byte more is an error.

The DB side carrying no type envelope is deliberate: SQL needs to see the **byte-for-byte original value**, and adding a type byte would give the plaintext lying in the database an envelope header, so `WHERE` comparisons would no longer match either.

---

## Features

![Feature design: two encryption paths, SQL fragments, key rotation, the type envelope, framework integrations, the CLI, the project pet](../../diagrams/en/features.svg)

### Application side: `AeadEncrypter` (the default choice)

| Method | What it does |
|--------|--------------|
| `new(&config)` | Validates at construction that the cipher is AEAD, that the key length matches, and that previous keys are the same length as the primary |
| `encrypt(value)` | Encrypts a value; a ciphertext already in this format is **returned as-is**. The check is an actual decryption attempt, not a look at the shape |
| `seal(value)` | Unconditionally encrypts, with no "is it already ciphertext" check |
| `decrypt(payload)` | Decrypts into a `Value`; any one key on the key ring succeeding is enough |
| `decrypt_text(payload)` | Decrypts and asserts that the result is a string |
| `decrypt_or_original(payload)` | The lenient version: returns the input as-is when it cannot be decrypted (an explicit choice) |
| `is_encrypted(value)` | Cheap shape check; touches no key, does no authentication |
| `rotate_to_current_key(payload)` | Reads with the old key, writes with the new one; input that is already plaintext is returned as-is |
| `cipher_name()` / `ring_len()` / `primary_key_hex()` | Diagnostics; the last one is the primary key in hex (`Zeroizing<String>`) |

The encryption entry points take `impl Into<Value>`: `&str` / `String` / `i64` / `i32` / `f64` / `bool` / `Option<T>` can all be passed directly. `None` maps to `Value::Null` — note that **`Null` gets encrypted into a ciphertext**, which is not the same thing as "no value"; whether to store a SQL `NULL` is the caller's decision, and this library will not make it for you.

### DB side: `DbEncrypter`

| Method | What it does |
|--------|--------------|
| `new(&config)` | Validates at construction that the cipher is deterministic ECB |
| `encrypt(plaintext)` | Deterministic encryption, producing ciphertext that can be bound straight into a `WHERE`; if the input is already an application-side payload it raises `Error::WrongFormat` |
| `decrypt(payload)` | Restores (for migration and the CLI, **not for queries**) |
| `decrypt_expr(column, driver)` | Emits the SQL fragment that lets the database decrypt for itself |
| `decrypt_expr_default(column)` | Same, with the dialect taken from the construction-time configuration |
| `is_encrypted(value)` | Shape check |
| `key_hex()` / `driver()` / `cipher_name()` | Diagnostics |

The input is a string rather than a type envelope — see the previous section.

### Configuration

`EncryptableConfig` has only four methods, the last three with defaults:

| Source | Entry point | Notes |
|--------|-------------|-------|
| Code | `ArrayConfig::new(key)` | `.with_cipher()` / `.with_previous_keys()` / `.with_db_driver()` |
| Environment | `EnvConfig::from_env()` | `ENCRYPTION_KEY` / `ENCRYPTION_CIPHER` / `ENCRYPTION_PREVIOUS_KEYS` / `ENCRYPTION_DB_DRIVER`, variable names character-for-character identical to the PHP version, so ops deployment scripts can be copied over |
| Tests | `EnvConfig::from_env_with(\|k\| ...)` | Injects the getter function and touches no process environment — `set_var` is `unsafe` in Rust 2024, and it data-races with threads reading env vars concurrently |

Accepted spellings for the key: a literal exactly the length the cipher requires, exactly 64 hex characters (decoded as 32 bytes), or a `base64:` prefix. The three spellings are equivalent; `encryptable keygen` prints two of the usable spellings (hex and the `base64:` prefix) — bare base64 does not work, since 44 characters counted as a literal is 44 bytes, and the length check rejects it.

### SQL fragments

```sql
-- MySQL / MariaDB
CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64(phone), 2 ), UNHEX('<hex>') ) USING 'UTF8' )

-- PostgreSQL (pgcrypto)
convert_from( decrypt( substring( decode(phone, 'base64') from 2 ), '\x<hex>'::bytea, 'aes-ecb' ), 'UTF8' )
```

`SUBSTRING(..., 2)` strips the version byte. Column names first pass an allowlist (first character a letter or underscore, the rest letters, digits, underscores or dots, and a dot must sit between two segments), so the fragment contains no user-controllable string at all.

### Optional serde integration (`--features serde`)

`encrypt_json<T: Serialize>` and `decrypt_json<T: DeserializeOwned>`: any serializable type is turned into JSON, put into the type envelope and then encrypted. The JSON therefore lies **inside authenticated ciphertext**, and no separate binary envelope has to be designed for it; a type mismatch (reading a `struct` with `Vec<i32>`) raises `Error::Unserialize`, not garbled data.

### CLI and the pet

8 commands: `keygen` / `encrypt` / `decrypt` / `rotate` / `db-encrypt` / `db-decrypt` / `sql` / `pet`; see "Usage" for how to call them. The pet artwork comes from `encryptable::pet::{NAME, TAGLINE, ASCII, SVG}`.

---

## Framework integrations

One opt-in feature per framework, and **a default build pulls in none of them**. They all do the same thing: hand the request guard [`Guard`](../../../src/guard.rs) to the handler, following each framework's own conventions.

### The request guard `Guard`

`Guard` is an `Arc`-shared encryption handle, `Clone` + `Send` + `Sync`, with the key ring resolved at construction and zero cost per request afterwards:

```rust
use encryptable::config::ArrayConfig;
use encryptable::Guard;

let guard = Guard::new(&ArrayConfig::new("<32-byte key>"))?;
// attach a DB side too if you need one (the DB side demands a deterministic cipher, so it gets its own config)
let guard = guard.with_db(&ArrayConfig::new("<the same key>").with_cipher("aes-256-ecb"))?;
```

### `Guarded`: pulling the guard out of a larger state

A real application's state struct holds more than one encrypter. Implement `Guarded` to point at the field holding the guard, and the adapter layer uses that to provide each framework's extractor:

```rust
use std::sync::Arc;
use encryptable::Guard;
use encryptable::integrations::Guarded;

#[derive(Clone)]
struct AppState {
    pool: Arc<DbPool>,
    encryption: Guard,          // the guard is one of its fields
}

impl Guarded for AppState {
    fn guard(&self) -> &Guard { &self.encryption }
}
```

### How each framework plugs in

| Framework | feature | Mechanism | How the handler gets it |
|-----------|---------|-----------|-------------------------|
| **axum** 0.8 | `axum` | Implements `FromRequestParts`, pulling from state via `Guarded` | `async fn h(guard: Guard)` |
| **bee-rust** 1.x | `bee-rust` | Routes take axum handlers directly, **reusing the axum adapter** | `async fn h(guard: Guard)` |
| **actix-web** 4 | `actix-web` | Implements `FromRequest`, reading the `Data<Guard>` in `app_data` | `async fn h(guard: Guard)` |
| **rocket** 0.5 | `rocket` | Implements the `FromRequest` request guard, reading `manage`d state | `fn h(guard: Guard)` |
| **poem** 3 | `poem` | Implements `FromRequest`, reading the extension injected by `.data(...)` | `async fn h(guard: Guard)` |
| **salvo** 1.0 | `salvo` | Implements `Extractible`, reading the `Depot` | `async fn h(guard: Guard)` |
| **warp** 0.4 | `warp` | No extractor trait; provides a `with_guard` combinator | `.and(with_guard(g)).map(\|g: Guard\| …)` |
| **e-cat** 4 | `ecat` | A standard tower `Layer`/`Service`, putting the guard into request extensions | `Extension<Guard>` |

```toml
[dependencies]
encryptable-rust = { version = "0.1", features = ["axum"] }
```

**[bee-rust](https://github.com/erikwang2013/bee-rust) and [e-cat](https://github.com/erikwang2013/e-cat) both sit on top of axum 0.8**: the former's routing takes axum handlers directly (state also goes through axum's `State`, so the `Guarded` path works unchanged); the latter's HTTP transport is axum and its middleware is tower, so the guard shape is simply "put a value into the request extensions". Both need only a thin layer.

### Extraction failures are always 500

`Guarded::guard()` returns a reference, so failing to get the guard can only be an **assembly error** — a missing `manage` / `app_data` / `with_state` / `data` at startup. The user did nothing wrong, so every adapter translates it uniformly into a `500` with a message naming the missing assembly step ([`GuardNotConfigured`](../../../src/integrations/mod.rs)), never a 4xx.

Failures of encryption/decryption **itself** (wrong key, altered ciphertext) are not handled here — they happen inside the handler body, and it is up to the application to decide between 500 and 422. This library does not make that decision for the application.

### e-cat's tower layer does not need boxing

`GuardLayer` neither rewrites responses nor errors; it only puts an `Extension` into the request, so `type Future = S::Future` passes the inner future straight through, with no `Pin<Box<dyn ...>>` and no dependency on `futures`. It has the same shape as e-cat's own `ValidateLayer` and can sit beside it in the same `ServiceBuilder`.

---

## Known limits

The following are boundaries that are **known and deliberately kept**. Read the reasoning before changing any of them — most are not defects waiting to be fixed, but properties of this path itself.

### The price of deterministic ECB: frequency analysis works

The same plaintext always produces the same ciphertext, which is the reason the DB path exists and also its price. On low-cardinality columns (gender, status, province, VIP or not) encryption ends up **almost as good as none** — an attacker needs no key: count how often each ciphertext appears and the distribution is restored; the rest is guessed from common sense. This path should only be used on columns that must be queryable by original value; everything else goes through the application side.

### `decrypt_expr` embeds the primary key into SQL text

The `UNHEX('<hex>')` / `'\x<hex>'::bytea` in the fragment *is* the primary key, so it lands in slow query logs, `pg_stat_statements`, and anywhere else statements are recorded. The key entering as hex rather than as a quoted string at least removes the path where one missed escape becomes injection — but **the leak itself is not solved**.

The recommended practice is not to use it for filtering: compute the ciphertext from the input with `encrypt()` first, then bind it as a parameter (`WHERE phone = ?`). That neither exposes the key nor forfeits the index on that column — wrapping the column name in `decrypt_expr` kills the index outright. `decrypt_expr` is for "I want plaintext in the `SELECT` list" and reporting scenarios.

### MySQL's `block_encryption_mode` trap

MySQL's `block_encryption_mode` session variable defaults to `aes-128-ecb`, and `AES_DECRYPT` goes through exactly that. With a 32-byte key you must first run:

```sql
SET block_encryption_mode = 'aes-256-ecb';
```

Otherwise MySQL silently XOR-folds the 32-byte key down to the 16 bytes it expects and **returns NULL without an error** — you get the hardest-to-debug symptom there is: "the query runs, the result is empty". This is **a defect lying dormant in the original PHP project**: the Rust version did not inherit it (the key length is fixed by the cipher at construction), but the default on the database side is not this library's to control — it can only be pointed out here.

### PostgreSQL and MySQL fail differently

`convert_from` **aborts the whole query with an error** on non-UTF-8 bytes; MySQL's `CONVERT(... USING 'UTF8')` returns NULL instead. The same cause (a misconfigured key, say) shows up as two different symptoms: "the query blew up" on one side, "the results are all NULL" on the other.

### No byte-level PHP interop

This is **deliberate**, not "just not done yet": the envelope was redesigned (hand-rolled HMAC removed, the `crypt:` dirty bit removed, the non-AEAD branch removed). Ciphertext written by PHP cannot be read by Rust, and vice versa. Existing columns must be migrated by re-encrypting on the application side.

### `is_encrypted` is a cheap shape check with false positives

It only does base64 decoding + version byte + minimum length; it **touches no key and does no authentication**. Plaintext whose base64-decoded first byte happens to be `0x01` (or `0x02`) is judged to be ciphertext, with probability around 1/256. When you truly need a definite answer, use `decrypt` (which really does authenticate once).

Incidentally: `encrypt()` does **not** use the shape check internally to decide "should this be encrypted again" — it genuinely attempts a decryption, precisely to avoid the pit the PHP version fell into (plaintext that looks like ciphertext being stored as-is and never decryptable again).

### The DB path ignores `previous_keys`

DB-side ciphertext recognises only the primary key. Rotating DB-side ciphertext goes through an upper-layer migration (rewriting the whole column), not the key ring — the hex key embedded in the SQL fragment is the primary key, and the other keys on the ring mean nothing to it.

### The birthday bound on GCM nonces

The application side uses a 96-bit random nonce. Under one key, after roughly 2^32 messages the chance of a nonce collision is no longer negligible (a collision breaks GCM's authentication and confidentiality at the same time). That ceiling is enough for the vast majority of workloads, but **do not put the same primary key on a column written a million times a second without rotating** — rotation exists for exactly this.

### Ciphertext is standard base64 and must be re-alphabeted before URLs

Ciphertext uses **standard base64**, whose alphabet contains `/` and `+`. Put it straight into a URL path and the `/` is taken for a path separator, so the request lands on a different route — presenting as **intermittent 404s**, because whether a `/` appears depends on the random nonce (about half the time).

To put ciphertext into a URL (path or query string), first switch to the base64url alphabet: `+`→`-`, `/`→`_`, and switch back on receipt. This is not this library's restriction, it is the URL's: any standard base64 going into a URL must be handled this way. The payload itself usually belongs in the request body, not the URL.

### No KDF: the key must be exactly the length the cipher requires

Keys are raw bytes — no salt, no iteration — so a captured ciphertext can be brute-forced at high speed. A weak passphrase therefore does not get "stretched" into a key; it is rejected outright with `Error::KeyLength` (a 16-byte key against a 32-byte cipher is likewise rejected). Generate keys with `encryptable keygen`; do not type them yourself. One more consequence: a **literal** key of exactly 64 hex characters is interpreted as hex, not as a 64-byte literal — this is so ops has a representation identical to the one in the SQL fragment.

---

## Request lifecycle

![Request lifecycle: HTTP request → framework routing → guard extraction → handler → encrypt/decrypt → database → response](../../diagrams/en/request-lifecycle.svg)

Only three things happen as a request crosses the framework integration layer:

1. **Routing**: the framework matches a handler in its own way.
2. **Extraction**: the adapter layer calls [`Guarded::guard()`](../../../src/integrations/mod.rs), cloning the `Arc` once. **This step never fails** — the guard comes from state, so if it compiles, it is there.
3. **Encryption/decryption**: the handler holds `guard` and works with it. The key ring was resolved at **startup**; nowhere along this path is an environment variable read, a string parsed, or a key derived.

What is worth remembering is **where failures happen**:

| Failure | When | Who responds |
|---------|------|--------------|
| No guard registered in state | Before extraction (a step missed during assembly) | The adapter layer → 500, with a message naming the missing step |
| Tag verification fails / no key on the ring can decrypt | Inside the handler body | **The caller** — this library does not decide for the application whether that is 500 or 422 |
| Wrong ciphertext format (application-side payload fed to the DB side) | Inside the handler body | The caller, and it is an explicit `Error::WrongFormat` |

The first row is the server's own assembly error; the user did nothing wrong, so it is a 5xx. The last two rows are business semantics and must be decided by the application — an endpoint reading a ciphertext column as if it were an ordinary column, and a manually triggered migration job, should respond completely differently to "cannot decrypt".

---

## Lifecycle

![Lifecycle: the value round trip, the two DB query paths, the four rotation steps](../../diagrams/en/lifecycle.svg)

### Application side: one round trip

```
write  plaintext / scalar → Value type envelope(tag || payload) → AES-GCM(random nonce, AAD = version byte)
       → 0x01 || nonce || ciphertext || tag → base64 → store
read   base64 → version byte check(0x01) → minimum length → try GCM authentication with each key in turn
       → the first one that succeeds yields the plaintext → Value::decode → back to the original type
```

The ring is ordered primary first, retired keys after. It deliberately **does not tell the caller** which key decrypted the payload — leaking "the Nth key" would leak the rotation's progress.

### DB side: the two query paths

```
① Equality match (recommended)   encrypt(input) → ciphertext → bind into WHERE phone = ?
                    Cost: one computation on the application side; Benefit: no key in SQL, that column's index is usable

② Decrypt in the SELECT list    decrypt_expr("phone", driver) → SQL fragment → hand it to the database to execute
                    Cost: the primary key embedded in SQL text, index dead; Benefit: the query structure stays as it is
```

**Use ① for filtering, ② for plaintext** — swap them and you pay both costs at once.

### Key rotation: four steps

| Step | Action | State at that moment |
|------|--------|----------------------|
| 1 | Change the primary key: `ENCRYPTION_KEY=<new>` | New data is written with the new key; **existing data becomes immediately unreadable** |
| 2 | Put the old key into `ENCRYPTION_PREVIOUS_KEYS` | Existing data is readable again; old and new ciphertexts coexist in the database |
| 3 | A background job calls `rotate_to_current_key()` in batches | Existing rows move one by one onto ciphertexts of the new primary key |
| 4 | Once no old ciphertext remains, drop `previous_keys` | Rotation complete; `ring_len()` is back to 1 |

There may be a gap between steps 1 and 2, but they **must ship as one change** — doing only step 1 turns all existing data into undecryptable bytes. Step 3 can run slowly; however long it takes, no data is lost; `rotate_to_current_key()` returns input that is already plaintext as-is, so the batch can call it across the whole table without a second thought. Before step 4, confirm the move is genuinely complete: leaving `previous_keys` in place throws no error, it just stays on the ring and piles up longer at the next rotation.

---

## Usage

### Zero-config start (environment variables)

```bash
# generate a key first; keygen prints both usable spellings of the same key (hex and the base64: prefix)
encryptable keygen

# paste one of them in
export ENCRYPTION_KEY=<that key>
export ENCRYPTION_CIPHER=aes-256-gcm          # the default; can be omitted
export ENCRYPTION_PREVIOUS_KEYS=old1,old2     # comma-separated; a JSON array is rejected
export ENCRYPTION_DB_DRIVER=mysql             # or pgsql / postgres
```

```rust
use encryptable::config::EnvConfig;
use encryptable::AeadEncrypter;

let encrypter = AeadEncrypter::new(&EnvConfig::from_env())?;
```

Without environment variables:

```rust
use encryptable::config::{ArrayConfig, DbDriver};
use encryptable::{AeadEncrypter, DbEncrypter};

// application side — the default path, used for every storage scenario
let app = AeadEncrypter::new(&ArrayConfig::new("0123456789abcdef0123456789abcdef"))?;

let c = app.encrypt("13800138000")?;      // also accepts i64 / f64 / bool — see Value's From impls
let v = app.decrypt(&c)?;                 // -> Value
let s = app.decrypt_text(&c)?;            // -> String
app.is_encrypted(&c);                     // cheap shape check, touches no key
app.rotate_to_current_key(&c)?;           // rotate: read with the old key, write with the new one
app.cipher_name(); app.ring_len();
app.decrypt_or_original("plain");         // the lenient version, an explicit choice

// DB side — only for columns that must be queried by original value
let db = DbEncrypter::new(
    &ArrayConfig::new("0123456789abcdef0123456789abcdef")
        .with_cipher("aes-256-ecb")
        .with_db_driver(DbDriver::Postgres),
)?;

let bound = db.encrypt("13800138000")?;   // deterministic, can be bound into WHERE
let plain = db.decrypt(&bound)?;          // for migration / CLI use
db.decrypt_expr("phone", DbDriver::Mysql)?;   // returns the SQL fragment string; the driver argument picks the dialect
db.is_encrypted(&bound); db.key_hex(); db.driver();
```

Rotation:

```rust
// swap the primary key, retire the old one into previous_keys — existing data still reads
let rotated = AeadEncrypter::new(
    &ArrayConfig::new("<new primary key>").with_previous_keys(vec!["<old primary key>".into()]),
)?;
rotated.decrypt_text(&old_ciphertext)?;                       // still readable
let moved = rotated.rotate_to_current_key(&old_ciphertext)?;  // moved onto the new primary key
```

### The two query recipes

```rust
// ① Filter: compute the ciphertext first, then bind it as a parameter (same for any driver) — no key in SQL, index usable
let cipher = db.encrypt(user_input)?;
// SELECT id FROM users WHERE phone = ?      -- the parameter is the cipher above

// ② Plaintext: let the database decrypt for itself — SELECT list only
let expr = db.decrypt_expr("phone", DbDriver::Mysql)?;
// SELECT id, <expr> AS phone FROM users WHERE id = ?
```

### CLI

```bash
encryptable keygen                       # generate a 32-byte primary key
encryptable pet                          # print the project pet

C=$(encryptable encrypt 13800138000)     # application-side encrypt
encryptable decrypt "$C"                 # application-side decrypt
encryptable rotate "$C"                  # re-encrypt with the current primary key

D=$(encryptable db-encrypt 13800138000)  # deterministic DB-side encryption (ENCRYPTION_CIPHER must be aes-256-ecb)
encryptable db-decrypt "$D"              # DB-side restore (for migration)
encryptable sql phone --driver mysql     # print the SQL fragment
```

Keys are read only from **environment variables**, never from argv — argv leaks through `ps` and shell history. Input can also come through a pipe: `printf 13800138000 | encryptable encrypt`. Exit codes: `0` success · `1` usage error · `2` configuration or cryptographic error.

---

## Development

```bash
cargo build
cargo test
cargo test --features serde
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

The default build has **146 tests passing** (plus 1 that is `#[ignore]`d by default and needs a real MySQL), and `--features serde` gives **152**. Each framework feature brings its own set of adapter tests (3–7 of them), compiled only when that feature is on:

```bash
cargo test --features axum        # one set per framework
cargo test --features actix-web
cargo test --features rocket
cargo test --features poem
cargo test --features salvo
cargo test --features warp
cargo test --features bee-rust
cargo test --features ecat
```

One integration test is `#[ignore]`d by default — it needs a real MySQL and is usually skipped:

```bash
ENCRYPTION_TEST_MYSQL=mysql://user:pass@localhost/db cargo test --test db_sql -- --ignored
```

There are two correctness anchors:

- **Golden vectors: byte-for-byte alignment with OpenSSL.** The DB path's PKCS#7 + ECB is hand-written, and `matches_openssl_byte_for_byte` in `src/encrypter/db.rs` pins it to the output of `openssl enc -aes-256-ecb` (the vector is produced by `printf 'hello' | openssl enc -aes-256-ecb -K 000102…1f -nosalt | base64 -w0`, with version byte `0x02` prepended and then base64). This is the only CI-verifiable proxy for "can the database read the bytes we write" — one padding block short, one byte-order slip, and this test goes red.
- **Properties: `tests/invariants.rs`.** Having given up byte-level interop with PHP, this crate has no ready-made cross-language vector to align with; instead there is a set of invariants: round-trip identity, tampering always rejected, wrong key always rejected, random nonces never repeating, DB-path determinism, and the two payload kinds never working with each other. The corpora are generated by a hand-written LCG rather than `proptest` / `quickcheck` — deterministic, reproducible, zero dependencies.

The whole rotation migration path (swap the primary key → old key into the ring → batch move → removal) is in `tests/rotation.rs`.

A runnable demo of both paths plus one complete rotation is in `examples/quickstart.rs`:

```bash
cargo run --example quickstart
```

---

## Reference: the original project

A Rust port of the PHP package **erikwang2013/encryptable**: <https://github.com/erikwang2013/encryptable>.

The two sides' **ciphertexts do not interoperate** (the envelope was redesigned, see "Known limits"), but **the configuration can be copied over** — the `ENCRYPTION_*` variable names, the cipher names (`aes-256-gcm` / `aes-256-ecb`) and the column-name spelling all match, so ops deployment scripts need no changes.

---

## Donate / Sponsor

If this project helps you, a donation is welcome (entirely voluntary).

| Alipay | WeChat Pay |
|--------|------------|
| ![Alipay](../../alipay.png) | ![WeChat Pay](../../weixinpay.png) |

### Global transfer (international wire)

**Recipient details**
- Recipient name: WANG KEXUN
- Recipient account number: 881015918251

**Receiving bank**
- ZA Bank SWIFT Code: AABLHKHHXXX
- Bank name: ZA Bank Limited
- Bank code: 387
- Bank address: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Cross-border correspondent bank (if required)**

Please note that this is cross-border correspondent (intermediary) bank information, not the receiving bank's. Ask your sending bank whether correspondent bank information needs to be supplied.

For incoming transfers in HKD, CNY and USD, the correspondent bank is Citibank:
- Bank name: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- Bank code: 006
- Branch name: Hong Kong Branch
- Branch code: 391
- Bank address: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

For incoming transfers in other currencies, the correspondent bank is BNY Mellon:
- Bank name: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- Bank address: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## License

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
