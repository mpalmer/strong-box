#[derive(Debug, thiserror::Error, thiserror_ext::Construct)]
#[non_exhaustive]
pub enum Error {
	#[error("failed to decrypt ciphertext")]
	Decryption,

	#[error("failed to encrypt plaintext")]
	Encryption,

	#[error("ciphertext decoding failure on {element}: {cause:?}")]
	Decoding {
		element: String,
		cause: ciborium_ll::Error<std::io::Error>,
	},

	#[error("ciphertext encoding failure on {element}: {cause}")]
	Encoding {
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
