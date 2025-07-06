use secrecy::ExposeSecret as _;

/// A key used by various kinds of [`StrongBox`](super::StrongBox) for encrypting or decrypting data.
#[derive(Debug)]
pub struct Key(secrecy::SecretBox<[u8; 32]>);

impl Key {
	pub fn expose_secret(&self) -> &[u8; 32] {
		self.0.expose_secret()
	}
}

impl Clone for Key {
	fn clone(&self) -> Self {
		Self(Box::new(*self.expose_secret()).into())
	}
}

impl From<Box<[u8; 32]>> for Key {
	fn from(k: Box<[u8; 32]>) -> Self {
		Key(k.into())
	}
}

/// Create a key suitable for use in a [`StrongBox`](super::StrongBox).
///
/// This isn't usually required in real-world usage, as you'll *usually* have your keys
/// stored somewhere out of the way.  However, for testing use, or the odd occasion when
/// encryption/decryption is very temporary, a simple function to generate a secure key
/// is useful to have laying around.
#[tracing::instrument(level = "debug")]
pub fn generate_key() -> Key {
	use rand::{rng, RngCore};

	let mut k = [0u8; 32];

	rng().fill_bytes(&mut k);

	Box::new(k).into()
}
