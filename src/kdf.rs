use hkdf::Hkdf;
use secrecy::ExposeSecret as _;
use sha2::Sha256;

use super::Key;

pub(crate) fn derive_key(key: &Key<[u8; 32]>, context: &[u8]) -> Key<[u8; 32]> {
	let hk = Hkdf::<Sha256>::from_prk(key.expose_secret()).expect("key not long enough");

	let mut output = [0u8; 32];

	hk.expand(context, &mut output).expect("KBKDF assploded");

	Key::new(output)
}
