use super::Error;

/// Core trait that all the various forms of encrypting StrongBoxes implement to provide encryption
/// / decryption functionality.
pub trait StrongBox {
	/// Encrypt secret data using the [`StrongBox`]'s encryption key, within the [`StrongBox`]'s specified context.
	///
	/// # Errors
	///
	/// Will return [`Error::Encryption`] or [`Error::Encoding`] in the (extremely
	/// unlikely) event something goes horribly wrong.
	fn encrypt(
		&self,
		plaintext: impl AsRef<[u8]>,
		context: impl AsRef<[u8]> + std::fmt::Debug,
	) -> Result<Vec<u8>, Error>;

	/// Decrypt a ciphertext, using any valid key for the [`StrongBox`], and validate that the ciphertext
	/// was encrypted with the specified context.
	///
	/// # Errors
	///
	/// Will return one of the following:
	/// * [`Error::Decryption`] if the ciphertext was encrypted with a different
	///   key, or a different context.
	/// * [`Error::Decoding`] if the ciphertext was malformed, which means that either the
	///   ciphertext was corrupted in storage or transit, or the data provided was never a
	///   ciphertext.
	fn decrypt(
		&self,
		ciphertext: impl AsRef<[u8]>,
		context: impl AsRef<[u8]> + std::fmt::Debug,
	) -> Result<Vec<u8>, Error>;
}
