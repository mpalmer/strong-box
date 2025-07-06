use hkdf::Hkdf;
use sha2::Sha256;

use super::Key;

pub(crate) fn derive_key(key: &Key, context: &[u8]) -> Key {
	let hk = Hkdf::<Sha256>::from_prk(key.expose_secret()).expect("key not long enough");

	let mut output = [0u8; 32];

	hk.expand(context, &mut output).expect("KBKDF assploded");

	Box::new(output).into()
}
