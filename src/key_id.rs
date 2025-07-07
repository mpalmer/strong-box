use ciborium_ll::Header;

use super::{Error, Key, kdf};

type Kid = [u8; 16];

#[allow(clippy::derived_hash_with_manual_eq)] // k1 == k2 => hash(k1) == hash(k2) will hold
#[derive(Clone, Copy, Debug, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub(super) struct KeyId(Kid);

impl KeyId {
	pub(super) fn as_bytes(&self) -> &Kid {
		&self.0
	}

	pub(super) fn encode(&self, enc: &mut ciborium_ll::Encoder<&mut Vec<u8>>) -> Result<(), Error> {
		enc.bytes(&self.0, None)
			.map_err(|e| Error::ciphertext_encoding("key_id", e))?;
		Ok(())
	}

	pub(super) fn decode(dec: &mut ciborium_ll::Decoder<&[u8]>) -> Result<Self, Error> {
		let Header::Bytes(len) = dec
			.pull()
			.map_err(|e| Error::ciphertext_decoding("key_id header", e))?
		else {
			return Err(Error::invalid_ciphertext("expected key_id"));
		};

		let mut segments = dec.bytes(len);

		let Ok(Some(mut segment)) = segments.pull() else {
			return Err(Error::invalid_ciphertext("bad key_id"));
		};

		let mut buf = [0u8; 32];
		let mut key_id: Kid = Default::default();

		if let Some(chunk) = segment
			.pull(&mut buf[..])
			.map_err(|e| Error::ciphertext_decoding("key_id", e))?
		{
			if chunk.len() != key_id.len() {
				return Err(Error::invalid_ciphertext("incorrect key_id length"));
			}
			key_id[..].copy_from_slice(chunk);
		} else {
			return Err(Error::invalid_ciphertext("short nonce"));
		}

		Ok(Self(key_id))
	}
}

impl PartialEq for KeyId {
	fn eq(&self, other: &Self) -> bool {
		constant_time_eq::constant_time_eq_n(&self.0, &other.0)
	}
}

impl Eq for KeyId {}

impl std::fmt::Display for KeyId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		for b in &self.0 {
			f.write_fmt(format_args!("{b:02x}"))?;
		}

		Ok(())
	}
}

/// Get a reasonably-unique ID for a key
#[tracing::instrument(level = "trace")]
pub(super) fn key_id(key: &Key) -> KeyId {
	let new_id: Kid = Default::default();

	KeyId(
		kdf::derive_key(key, b"key_id").expose_secret()[0..new_id.len()]
			.try_into()
			.expect("key_id slice did not fit into key_id array"),
	)
}
