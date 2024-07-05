use chacha20poly1305::{
	aead::{Aead as _, Payload},
	ChaCha20Poly1305, KeyInit as _,
};
use rand::{thread_rng, RngCore};
use secrecy::ExposeSecret as _;
use std::{collections::HashMap, fmt::Debug};

use super::{Error, Key, KeyId, StrongBox};

/// A secure symmetric encryption container, supporting key rotation and AAD contexts.
///
/// This is your basic, Mark 1 mod 0 [`StrongBox`].  Given an encryption key, it will
/// encrypt data all day long with a modern, fast cipher (ChaCha20) with integrity protection and
/// authenticated additional data (using Poly1305).  If provided with one or more decryption keys,
/// it will decrypt data that was encrypted with *any* of those keys, giving you the ability to
/// "rotate" your key over time, by creating a new key, making it the new encryption key, and
/// keeping the old key in the set of "decryption" keys until such time as all data has been
/// re-encrypted with the new key.
///
/// The "authenticated additional data" is a mouthful, but what it means is that when you encrypt
/// data, you provide the encryption with a "context", such as the ID of the user that the
/// encrypted data belongs to.  When you decrypt the data again, you provide the ID of the user the
/// data belongs to, and if they don't match, decryption fails.  Why is that useful?  Because if
/// an attacker gets write access to the database, and moves encrypted data from one user to
/// another, Bad Things can happen.  [This Security StackExchange answer](https://security.stackexchange.com/a/179279/167630) is an excellent explanation of
/// why an encryption context is useful.
///
/// # Example
///
/// ```rust
/// use strong_box::{Error, StaticStrongBox, StrongBox};
/// # fn main() -> Result<(), Error> {
///
/// // A couple of keys are always useful to have
/// let old_key = strong_box::generate_key();
/// let new_key = strong_box::generate_key();
///
/// let old_strongbox = StaticStrongBox::new(old_key.clone(), [old_key]);
/// let new_strongbox = StaticStrongBox::new(new_key.clone(), [new_key]);
/// // This StaticStrongBox encrypts with `new_key`, but can decrypt ciphertexts
/// // encrypted with *either* `new_key` *or* `old_key`
/// let fallback_strongbox = StaticStrongBox::new(new_key.clone(), vec![new_key, old_key]);
///
/// /////////////////////////////////////////////////////////
/// // A ciphertext encrypted using the old key
///
/// let ciphertext = old_strongbox.encrypt(b"Hello, old world!", b"some context")?;
///
/// // We'd *hope* that we can decrypt what we encrypted
/// assert_eq!(
///     b"Hello, old world!".to_vec(),
///     old_strongbox.decrypt(&ciphertext, b"some context")?
/// );
///
/// // A StaticStrongBox that uses a different key won't be able to decrypt
/// let result = new_strongbox.decrypt(&ciphertext, b"some context");
/// assert!(matches!(result, Err(Error::Decryption)));
///
/// // Also, a StaticStrongBox that uses the right key won't decrypt if the context isn't the
/// // same as was used to encrypt
/// let result = old_strongbox.decrypt(&ciphertext, b"a different context");
/// assert!(matches!(result, Err(Error::Decryption)));
///
/// // However, magic of magicks, the fallback StaticStrongBox can do the job!
/// assert_eq!(
///     b"Hello, old world!".to_vec(),
///     fallback_strongbox.decrypt(&ciphertext, b"some context")?
/// );
///
/// //////////////////////////////////////////////////////////////
/// // Now, let's try a ciphertext encrypted using the new key
///
/// let ciphertext = new_strongbox.encrypt(b"Hello, new world!", b"new context")?;
///
/// // Again, the same StaticStrongBox should be able to decrypt
/// assert_eq!(
///     b"Hello, new world!".to_vec(),
///     new_strongbox.decrypt(&ciphertext, b"new context")?
/// );
///
/// // Unsurprisingly, the fallback StaticStrongBox can decrypt it too, as it uses the same key
/// assert_eq!(
///     b"Hello, new world!".to_vec(),
///     fallback_strongbox.decrypt(&ciphertext, b"new context")?
/// );
///
/// // A StaticStrongBox using just the old key won't be able to decrypt, though
/// let result = old_strongbox.decrypt(&ciphertext, b"new context");
/// assert!(matches!(result, Err(Error::Decryption)));
///
/// // And again, the right StaticStrongBox but the wrong context won't decrypt
/// let result = new_strongbox.decrypt(&ciphertext, b"some other context");
/// assert!(matches!(result, Err(Error::Decryption)));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct StaticStrongBox {
	encryption_key: Key<[u8; 32]>,
	encryption_key_id: KeyId,
	decryption_keys: HashMap<KeyId, Key<[u8; 32]>>,
}

impl StaticStrongBox {
	/// Create a new [`StaticStrongBox`].
	#[tracing::instrument(level = "debug", skip(enc_key, dec_keys))]
	pub fn new(
		enc_key: impl Into<Key<[u8; 32]>>,
		dec_keys: impl IntoIterator<Item = impl Into<Key<[u8; 32]>>>,
	) -> Self {
		let mut key_map: HashMap<KeyId, Key<[u8; 32]>> = HashMap::default();

		for key in dec_keys.into_iter() {
			let key = key.into();
			let key_id = super::key_id(&key);
			tracing::debug!(%key_id, "Including decryption key");
			key_map.insert(key_id, key);
		}

		let enc_key = enc_key.into();
		let enc_key_id = super::key_id(&enc_key);
		tracing::debug!("Encryption key is {enc_key_id}");

		Self {
			encryption_key_id: enc_key_id,
			encryption_key: enc_key,
			decryption_keys: key_map,
		}
	}

	pub(crate) fn decrypt_ciphertext(
		&self,
		ciphertext: &Ciphertext,
		ctx: &[u8],
	) -> Result<Vec<u8>, Error> {
		if let Some(key) = self.decryption_keys.get(&ciphertext.key_id) {
			tracing::debug!(key_id=%ciphertext.key_id, "Decrypting");

			let mut aad = Vec::<u8>::new();
			aad.extend_from_slice(ctx.as_ref());
			aad.extend_from_slice(ciphertext.key_id.as_bytes());
			aad.extend_from_slice(&ciphertext.nonce);

			let cipher = ChaCha20Poly1305::new(key.expose_secret().into());
			let payload = Payload {
				msg: &ciphertext.ciphertext,
				aad: &aad,
			};
			cipher
				.decrypt((&ciphertext.nonce[..]).into(), payload)
				.map_err(|_| Error::Decryption)
		} else {
			tracing::debug!(key_id=%ciphertext.key_id, "Decryption key not found");
			Err(Error::Decryption)
		}
	}
}

impl StrongBox for StaticStrongBox {
	#[tracing::instrument(level = "debug", skip(plaintext))]
	fn encrypt(
		&self,
		plaintext: impl AsRef<[u8]>,
		ctx: impl AsRef<[u8]> + Debug,
	) -> Result<Vec<u8>, Error> {
		let cipher = ChaCha20Poly1305::new((self.encryption_key.expose_secret()).into());
		let mut rng = thread_rng();
		let mut nonce = [0u8; 12];
		rng.fill_bytes(&mut nonce);

		let mut aad = Vec::<u8>::new();
		aad.extend_from_slice(ctx.as_ref());
		aad.extend_from_slice(self.encryption_key_id.as_bytes());
		aad.extend_from_slice(&nonce);

		let ciphertext = cipher
			.encrypt(
				(&nonce).into(),
				Payload {
					msg: plaintext.as_ref(),
					aad: &aad,
				},
			)
			.map_err(|_| Error::Encryption)?;
		tracing::debug!(key_id=%self.encryption_key_id, "Encrypting");

		Ciphertext::new(self.encryption_key_id, nonce, ciphertext).to_bytes()
	}

	#[tracing::instrument(level = "debug", skip(ciphertext))]
	fn decrypt(
		&self,
		ciphertext: impl AsRef<[u8]>,
		ctx: impl AsRef<[u8]> + Debug,
	) -> Result<Vec<u8>, Error> {
		let ciphertext = Ciphertext::try_from(ciphertext.as_ref())?;

		self.decrypt_ciphertext(&ciphertext, ctx.as_ref())
	}
}

// This makes more sense in base64
const CIPHERTEXT_MAGIC: [u8; 3] = [0xb1, 0xb8, 0xf5];

#[derive(Clone, Debug)]
pub(crate) struct Ciphertext {
	pub(crate) key_id: KeyId,
	pub(crate) nonce: [u8; 12],
	pub(crate) ciphertext: Vec<u8>,
}

impl Ciphertext {
	pub(crate) fn new(key_id: KeyId, nonce: [u8; 12], ciphertext: Vec<u8>) -> Self {
		Self {
			key_id,
			nonce,
			ciphertext,
		}
	}

	pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Error> {
		use ciborium_ll::{Encoder, Header};

		let mut v: Vec<u8> = Vec::new();

		v.extend_from_slice(&CIPHERTEXT_MAGIC);

		let mut enc = Encoder::from(&mut v);
		enc.push(Header::Array(Some(3)))
			.map_err(|e| Error::encoding("key_id", e))?;
		self.key_id.encode(&mut enc)?;
		enc.bytes(&self.nonce, None)
			.map_err(|e| Error::encoding("nonce", e))?;
		enc.bytes(&self.ciphertext, None)
			.map_err(|e| Error::encoding("ciphertext", e))?;

		tracing::debug!(
			nonce = self
				.nonce
				.iter()
				.map(|i| format!("{i:02x}"))
				.collect::<Vec<_>>()
				.join(""),
			ct = self
				.ciphertext
				.iter()
				.map(|i| format!("{i:02x}"))
				.collect::<Vec<_>>()
				.join(""),
			"{}",
			v.iter()
				.map(|i| format!("{i:02x}"))
				.collect::<Vec<_>>()
				.join("")
		);
		Ok(v)
	}
}

impl TryFrom<&[u8]> for Ciphertext {
	type Error = Error;

	fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
		use ciborium_ll::{Decoder, Header};

		if b.len() < 21 {
			return Err(Error::invalid_ciphertext("too short"));
		}

		if b[0..3] != CIPHERTEXT_MAGIC {
			tracing::debug!(magic=?CIPHERTEXT_MAGIC, actual=?b[0..3]);
			return Err(Error::invalid_ciphertext("incorrect magic"));
		}

		let mut dec = Decoder::from(&b[3..]);

		let Header::Array(Some(3)) = dec.pull().map_err(|e| Error::decoding("array", e))? else {
			return Err(Error::invalid_ciphertext("expected array"));
		};

		let key_id = KeyId::decode(&mut dec)?;

		// CBOR's great, until you have to deal with segmented bytestrings...
		let Header::Bytes(len) = dec.pull().map_err(|e| Error::decoding("nonce header", e))? else {
			return Err(Error::invalid_ciphertext("expected nonce"));
		};

		let mut segments = dec.bytes(len);

		let Ok(Some(mut segment)) = segments.pull() else {
			return Err(Error::invalid_ciphertext("bad nonce"));
		};

		let mut buf = [0u8; 1024];
		let mut nonce = [0u8; 12];

		if let Some(chunk) = segment
			.pull(&mut buf[..])
			.map_err(|e| Error::decoding("nonce", e))?
		{
			// Is this necessary?  Probably better to be safe than sorry
			nonce[..].copy_from_slice(chunk);
		} else {
			return Err(Error::invalid_ciphertext("short nonce"));
		}

		// ibid.
		let Header::Bytes(len) = dec
			.pull()
			.map_err(|e| Error::decoding("ciphertext header", e))?
		else {
			return Err(Error::invalid_ciphertext("expected ciphertext"));
		};

		let mut segments = dec.bytes(len);

		let Ok(Some(mut segment)) = segments.pull() else {
			return Err(Error::invalid_ciphertext("bad ciphertext"));
		};

		let mut ciphertext: Vec<u8> = Vec::new();

		while let Some(chunk) = segment
			.pull(&mut buf[..])
			.map_err(|e| Error::decoding("ciphertext", e))?
		{
			ciphertext.extend_from_slice(chunk);
		}

		Ok(Self {
			key_id,
			nonce,
			ciphertext,
		})
	}
}
