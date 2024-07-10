#[derive(Debug, thiserror::Error, thiserror_ext::Construct)]
#[non_exhaustive]
pub enum Error {
	#[error("failed to decrypt ciphertext")]
	Decryption,

	#[error("failed to encrypt plaintext")]
	Encryption,

	#[error("decoding failure: {cause:?}")]
	Decoding {
		#[from]
		cause: ciborium::de::Error<std::io::Error>,
	},

	#[error("encoding failure: {cause:?}")]
	Encoding {
		#[from]
		cause: ciborium::ser::Error<std::io::Error>,
	},

	#[error("ciphertext decoding failure on {element}: {cause:?}")]
	CiphertextDecoding {
		element: String,
		cause: ciborium_ll::Error<std::io::Error>,
	},

	#[error("ciphertext encoding failure on {element}: {cause}")]
	CiphertextEncoding {
		element: String,
		cause: std::io::Error,
	},

	#[error("CAN'T HAPPEN: {0}")]
	Insanity(String),

	#[error("invalid ciphertext: {0}")]
	InvalidCiphertext(String),

	#[error("invalid key: {0}")]
	InvalidKey(String),
}
