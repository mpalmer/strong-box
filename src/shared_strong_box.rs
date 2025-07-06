use secrecy::{ExposeSecret as _, SecretBox, SecretSlice};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use super::{Error, Key, StaticStrongBox, StrongBox};

const PRIVATE_KEY: u8 = 0;
const PUBLIC_KEY: u8 = 1;

pub struct SharedStrongBoxKey {
	key: Option<SecretBox<StaticSecret>>,
	public: PublicKey,
}

impl std::fmt::Debug for SharedStrongBoxKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		f.debug_struct("SharedStrongBoxKey")
			.field("public", &self.public())
			.finish()
	}
}

impl SharedStrongBoxKey {
	fn new() -> Self {
		Self::new_from_key(StaticSecret::random())
	}

	fn new_from_key(key: StaticSecret) -> Self {
		SharedStrongBoxKey {
			public: (&key).into(),
			key: Some(SecretBox::new(Box::new(key))),
		}
	}

	fn new_from_pubkey(key: [u8; 32]) -> Self {
		SharedStrongBoxKey {
			public: PublicKey::from(key),
			key: None,
		}
	}

	fn diffie_hellman(&self, pubkey: &PublicKey) -> Option<SharedSecret> {
		self.key
			.as_ref()
			.map(|k| k.expose_secret().diffie_hellman(pubkey))
	}

	pub fn private(&self) -> Option<SecretSlice<u8>> {
		self.key.as_ref().map(|k| {
			let mut v = vec![PRIVATE_KEY];
			v.extend_from_slice(k.expose_secret().as_bytes());
			v.into()
		})
	}

	pub fn public(&self) -> Vec<u8> {
		let mut v = vec![PUBLIC_KEY];

		v.extend_from_slice(self.public.as_bytes());

		v
	}
}

impl TryFrom<&Vec<u8>> for SharedStrongBoxKey {
	type Error = Error;

	fn try_from(k: &Vec<u8>) -> Result<Self, Error> {
		k[..].try_into()
	}
}

impl TryFrom<&[u8]> for SharedStrongBoxKey {
	type Error = Error;

	fn try_from(k: &[u8]) -> Result<Self, Error> {
		if k.len() != 33 {
			return Err(Error::invalid_key("invalid key length"));
		}

		let inkey: [u8; 32] = k[1..33].try_into().expect("failed to read key");

		match k.first() {
			Some(&PRIVATE_KEY) => Ok(SharedStrongBoxKey::new_from_key(StaticSecret::from(inkey))),
			Some(&PUBLIC_KEY) => Ok(SharedStrongBoxKey::new_from_pubkey(inkey)),
			Some(n) => Err(Error::invalid_key(format!("invalid type byte {n}"))),
			None => Err(Error::invalid_key("how the heck did we get here?!?")),
		}
	}
}

#[derive(Debug)]
pub struct SharedStrongBox {
	key: SharedStrongBoxKey,
}

impl SharedStrongBox {
	pub fn generate_key() -> SharedStrongBoxKey {
		SharedStrongBoxKey::new()
	}

	pub fn new(key: SharedStrongBoxKey) -> Self {
		Self { key }
	}
}

impl StrongBox for SharedStrongBox {
	#[tracing::instrument(level = "debug", skip(plaintext))]
	fn encrypt(
		&self,
		plaintext: impl AsRef<[u8]>,
		ctx: impl AsRef<[u8]> + std::fmt::Debug,
	) -> Result<Vec<u8>, Error> {
		let tmp_key = EphemeralSecret::random();
		let tmp_pubkey: PublicKey = (&tmp_key).into();

		let box_key = tmp_key.diffie_hellman(&self.key.public);

		if !box_key.was_contributory() {
			return Err(Error::Encryption);
		}

		let mut aad = Vec::<u8>::new();
		aad.extend_from_slice(ctx.as_ref());
		aad.extend_from_slice(tmp_pubkey.as_bytes());

		let strong_box = StaticStrongBox::new(Box::new(box_key.to_bytes()), Vec::<Key>::new());
		let ciphertext = strong_box.encrypt(plaintext.as_ref(), &aad)?;

		Ciphertext::new(tmp_pubkey.to_bytes(), ciphertext).to_bytes()
	}

	#[tracing::instrument(level = "debug", skip(ciphertext))]
	fn decrypt(
		&self,
		ciphertext: impl AsRef<[u8]>,
		ctx: impl AsRef<[u8]> + std::fmt::Debug,
	) -> Result<Vec<u8>, Error> {
		let ciphertext = Ciphertext::try_from(ciphertext.as_ref())?;

		let box_key = self
			.key
			.diffie_hellman(&PublicKey::from(ciphertext.pubkey))
			.ok_or_else(|| {
				Error::invalid_key("this SharedStrongBox does not have a private key")
			})?;

		if !box_key.was_contributory() {
			return Err(Error::Encryption);
		}

		let box_key = box_key.to_bytes();

		let mut aad = Vec::<u8>::new();
		aad.extend_from_slice(ctx.as_ref());
		aad.extend_from_slice(&ciphertext.pubkey);

		let strong_box = StaticStrongBox::new(Box::new(box_key), vec![Box::new(box_key)]);

		strong_box.decrypt(&ciphertext.ciphertext, &aad)
	}
}

const CIPHERTEXT_MAGIC: [u8; 3] = [0xB2, 0xC6, 0xF5];

#[derive(Clone, Debug)]
struct Ciphertext {
	pubkey: [u8; 32],
	ciphertext: Vec<u8>,
}

impl Ciphertext {
	pub(crate) fn new(pubkey: [u8; 32], ciphertext: Vec<u8>) -> Self {
		Self { pubkey, ciphertext }
	}

	pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Error> {
		use ciborium_ll::{Encoder, Header};

		let mut v: Vec<u8> = Vec::new();

		v.extend_from_slice(&CIPHERTEXT_MAGIC);

		let mut enc = Encoder::from(&mut v);
		enc.push(Header::Array(Some(2)))
			.map_err(|e| Error::ciphertext_encoding("array", e))?;
		enc.bytes(&self.pubkey, None)
			.map_err(|e| Error::ciphertext_encoding("pubkey", e))?;
		enc.bytes(&self.ciphertext, None)
			.map_err(|e| Error::ciphertext_encoding("ciphertext", e))?;

		Ok(v)
	}
}

impl TryFrom<&[u8]> for Ciphertext {
	type Error = Error;

	fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
		use ciborium_ll::{Decoder, Header};

		if b.len() < 37 {
			return Err(Error::invalid_ciphertext("too short"));
		}

		if b[0..3] != CIPHERTEXT_MAGIC {
			return Err(Error::invalid_ciphertext("incorrect magic"));
		}

		let mut dec = Decoder::from(&b[3..]);

		let Header::Array(Some(2)) = dec
			.pull()
			.map_err(|e| Error::ciphertext_decoding("array", e))?
		else {
			return Err(Error::invalid_ciphertext("expected array"));
		};

		// CBOR's great, until you have to deal with segmented bytestrings...
		let Header::Bytes(len) = dec
			.pull()
			.map_err(|e| Error::ciphertext_decoding("pubkey header", e))?
		else {
			return Err(Error::invalid_ciphertext("expected pubkey"));
		};

		let mut segments = dec.bytes(len);

		let Ok(Some(mut segment)) = segments.pull() else {
			return Err(Error::invalid_ciphertext("bad pubkey"));
		};

		let mut buf = [0u8; 1024];
		let mut pubkey = [0u8; 32];

		if let Some(chunk) = segment
			.pull(&mut buf[..])
			.map_err(|e| Error::ciphertext_decoding("pubkey", e))?
		{
			if chunk.len() != pubkey.len() {
				return Err(Error::invalid_ciphertext("bad pubkey length"));
			}
			pubkey[..].copy_from_slice(chunk);
		} else {
			return Err(Error::invalid_ciphertext("short pubkey"));
		}

		// ibid.
		let Header::Bytes(len) = dec
			.pull()
			.map_err(|e| Error::ciphertext_decoding("ciphertext header", e))?
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
			.map_err(|e| Error::ciphertext_decoding("ciphertext", e))?
		{
			ciphertext.extend_from_slice(chunk);
		}

		Ok(Self { pubkey, ciphertext })
	}
}
