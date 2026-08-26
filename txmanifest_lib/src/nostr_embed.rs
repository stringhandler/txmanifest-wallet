//! Signing a nostr event for a rangeproof embed.
//!
//! A manifest declares the *unsigned* fields — kind, content, tags — and names a wallet
//! key. The engine fills in `pubkey`, `id` and `sig`, so what lands on chain is a
//! complete NIP-01 event that a relay will accept.
//!
//! Signing here, at the authoring end, is what makes a bridge that republishes these
//! events a transport rather than an authority: the secret key never leaves the wallet,
//! and the bridge cannot forge an event on this author's behalf. It also runs on a view
//! key that cannot spend, so reading the chain and writing to nostr stay separate powers.
//!
//! The `nostr` crate does the framing and the id, at the same major version the
//! `liquid-nostr-bridge` relay verifies with — a writer and a reader that disagree about
//! NIP-01 serialization fail silently, so they are held to one implementation.

use anyhow::{Context, Result};
use nostr::prelude::*;

use crate::context::ExecutionContext;
use crate::eval;
use crate::manifest::NostrEmbed;
use crate::wallet::WalletFile;

/// What was signed, for the build report.
#[derive(Debug)]
pub struct SignedEvent {
    /// The event as JSON — the bytes that go into the rangeproof.
    pub json: Vec<u8>,
    /// The author's x-only pubkey (nostr identity), hex.
    pub pubkey: String,
    /// The event id, hex.
    pub id: String,
    /// The wallet derivation path the signature came from.
    pub key_path: String,
}

/// Build and sign the event an output's `rangeproof_embed.nostr` describes.
pub fn build(
    spec: &NostrEmbed,
    ctx: &ExecutionContext,
    wallet: &WalletFile,
) -> Result<SignedEvent> {
    let key_spec = spec.sign_with.as_deref().unwrap_or("wallet");
    let key_path = crate::wallet::resolve_key_path(wallet, &eval::eval_text(key_spec, ctx))?;
    let sk = crate::wallet::derive_secret_key(wallet, &key_path)?;
    let keys = Keys::new(
        SecretKey::from_slice(&sk.secret_bytes())
            .map_err(|e| anyhow::anyhow!("Derived key at '{key_path}' is not a valid nostr key: {e}"))?,
    );

    let content = eval::eval_text(&spec.content, ctx);
    let mut builder = EventBuilder::new(Kind::from(spec.kind.unwrap_or(1)), &content);

    for (i, tag) in spec.tags.as_deref().unwrap_or_default().iter().enumerate() {
        let resolved: Vec<String> = tag.iter().map(|v| eval::eval_text(v, ctx)).collect();
        builder = builder.tag(
            Tag::parse(resolved)
                .with_context(|| format!("nostr tag {i} ({tag:?}) is not a valid NIP-01 tag"))?,
        );
    }

    if let Some(at) = &spec.created_at {
        let secs = eval::eval_amount(at, ctx).context("nostr created_at")?;
        builder = builder.custom_created_at(Timestamp::from_secs(secs));
    }

    let event = builder
        .sign_with_keys(&keys)
        .context("could not sign the nostr event")?;

    let json = event.as_json().into_bytes();
    anyhow::ensure!(
        json.len() <= crate::rangeproof::MAX_PAYLOAD,
        "the signed nostr event is {} bytes but only {} fit in a rangeproof; \
         the content is {} bytes and the signing overhead is {}",
        json.len(),
        crate::rangeproof::MAX_PAYLOAD,
        content.len(),
        json.len().saturating_sub(content.len()),
    );

    Ok(SignedEvent {
        json,
        pubkey: event.pubkey.to_hex(),
        id: event.id.to_hex(),
        key_path,
    })
}

/// If a payload is a signed nostr event, render it for a human; otherwise `None`.
///
/// The event's own JSON is the payload — the exact bytes that were embedded — so it is
/// what gets shown, pretty-printed. A prose summary would have to leave fields out, and
/// the one field it is most tempting to omit is `sig`, whose absence is indistinguishable
/// from a payload that never carried one. Printing the record verbatim means a reader can
/// see the signature, hand the compact form straight to a relay, and check both against
/// what the chain actually holds.
pub fn describe(payload: &[u8]) -> Option<String> {
    let json = std::str::from_utf8(payload).ok()?;
    let event = Event::from_json(json).ok()?;

    // Re-serialize rather than reflow the input: this is the canonical NIP-01 form, and a
    // mismatch with the payload would itself be worth seeing.
    let compact = event.as_json();
    let pretty = serde_json::from_str::<serde_json::Value>(&compact)
        .ok()
        .and_then(|v| serde_json::to_string_pretty(&v).ok())
        .unwrap_or_else(|| compact.clone());

    let verdict = match event.verify() {
        Ok(()) => "signature verifies".to_string(),
        Err(e) => format!("SIGNATURE DOES NOT VERIFY ({e}) — a relay will reject this"),
    };

    Some(format!(
        "nostr event, {} bytes, {verdict}\n{pretty}",
        payload.len(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> WalletFile {
        WalletFile { network: "testnet".to_string(), mnemonic: MNEMONIC.to_string() }
    }

    fn spec(content: &str) -> NostrEmbed {
        NostrEmbed {
            kind: None,
            content: content.to_string(),
            tags: None,
            created_at: None,
            sign_with: None,
        }
    }

    #[test]
    fn signs_with_the_wallet_key_by_default() {
        let w = wallet();
        let ctx = ExecutionContext::new();
        let signed = build(&spec("hello from a rangeproof"), &ctx, &w).unwrap();

        // The nostr identity is the key the wallet already publishes, not a new one.
        let (expected, path) = crate::wallet::wallet_signing_pubkey(&w).unwrap();
        assert_eq!(signed.pubkey, expected);
        assert_eq!(signed.key_path, path);

        // And a relay will take it.
        let event = Event::from_json(String::from_utf8(signed.json).unwrap()).unwrap();
        event.verify().expect("a relay rejects anything that does not verify");
        assert_eq!(event.content, "hello from a rangeproof");
        assert_eq!(event.kind.as_u16(), 1);
    }

    #[test]
    fn honours_kind_tags_and_created_at() {
        let w = wallet();
        let ctx = ExecutionContext::new();
        let mut s = spec("tagged");
        s.kind = Some(30023);
        s.tags = Some(vec![
            vec!["t".to_string(), "liquid".to_string()],
            vec!["d".to_string(), "an-identifier".to_string()],
        ]);
        s.created_at = Some(serde_json::json!(1_700_000_000u64));

        let signed = build(&s, &ctx, &w).unwrap();
        let event = Event::from_json(String::from_utf8(signed.json).unwrap()).unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind.as_u16(), 30023);
        assert_eq!(event.created_at.as_secs(), 1_700_000_000);
        let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.clone().to_vec()).collect();
        assert!(tags.contains(&vec!["t".to_string(), "liquid".to_string()]), "tags: {tags:?}");

        // A pinned created_at is the only way the id is reproducible, so check that it is.
        let again = build(&s, &ctx, &w).unwrap();
        assert_eq!(again.id, signed.id);
    }

    #[test]
    fn sign_with_selects_a_different_identity() {
        let w = wallet();
        let ctx = ExecutionContext::new();
        let mut s = spec("as the oracle");
        s.sign_with = Some("oracle".to_string());

        let signed = build(&s, &ctx, &w).unwrap();
        let (oracle_pub, _) = (
            crate::wallet::derive_schnorr_pubkey(&w, crate::wallet::oracle_key_path(&w)).unwrap(),
            (),
        );
        assert_eq!(signed.pubkey, oracle_pub);
        assert_ne!(signed.pubkey, crate::wallet::wallet_signing_pubkey(&w).unwrap().0);

        // An explicit path works too, and reaches the same key as the alias.
        s.sign_with = Some(crate::wallet::oracle_key_path(&w).to_string());
        assert_eq!(build(&s, &ctx, &w).unwrap().pubkey, oracle_pub);
    }

    #[test]
    fn content_resolves_references() {
        let w = wallet();
        let mut ctx = ExecutionContext::new();
        ctx.set_param("headline", "resolved from a param");
        let mut s = spec("params.headline");
        s.tags = Some(vec![vec!["t".to_string(), "params.headline".to_string()]]);

        let signed = build(&s, &ctx, &w).unwrap();
        let event = Event::from_json(String::from_utf8(signed.json).unwrap()).unwrap();
        assert_eq!(event.content, "resolved from a param");
        let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.clone().to_vec()).collect();
        assert_eq!(tags[0][1], "resolved from a param");
    }

    #[test]
    fn refuses_content_that_cannot_fit() {
        let w = wallet();
        let ctx = ExecutionContext::new();
        let err = build(&spec(&"x".repeat(crate::rangeproof::MAX_PAYLOAD)), &ctx, &w)
            .unwrap_err()
            .to_string();
        assert!(err.contains("fit in a rangeproof"), "unhelpful message: {err}");
    }

    #[test]
    fn rejects_an_unknown_key_name() {
        let w = wallet();
        let ctx = ExecutionContext::new();
        let mut s = spec("who signs this?");
        s.sign_with = Some("treasurer".to_string());
        let err = build(&s, &ctx, &w).unwrap_err().to_string();
        assert!(err.contains("Unknown key 'treasurer'"), "unhelpful message: {err}");
    }

    #[test]
    fn describes_only_what_is_actually_an_event() {
        let w = wallet();
        let ctx = ExecutionContext::new();
        let signed = build(&spec("readable"), &ctx, &w).unwrap();
        let rendered = describe(&signed.json).expect("a signed event describes as one");
        assert!(rendered.contains("signature verifies"), "{rendered}");
        assert!(rendered.contains("readable"), "{rendered}");

        // Every NIP-01 field is shown, `sig` above all: a summary that omits it looks
        // exactly like a payload that never carried one, which is what prompted this.
        for field in ["\"id\"", "\"pubkey\"", "\"created_at\"", "\"kind\"", "\"tags\"", "\"content\"", "\"sig\""] {
            assert!(rendered.contains(field), "{field} must be visible in:\n{rendered}");
        }
        assert!(rendered.contains(&signed.pubkey), "{rendered}");
        assert!(rendered.contains(&signed.id), "{rendered}");

        assert!(describe(b"just a plain message").is_none());
    }
}


