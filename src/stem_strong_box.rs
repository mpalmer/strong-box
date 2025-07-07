use std::{fmt::Debug, time::Duration};

#[cfg(doc)]
use super::StrongBox;
use super::{Key, RotatingStrongBox, StaticStrongBox, kdf};

/// A way to derive many [`StrongBox`]es from one set of keys.
///
/// Splitting different encryption usages to use different keys prevents accidental misuse,
/// and reduces the chances of insecurity from overuse.  Rather than have to manage a whole
/// bunch of keys, though, a [`StemStrongBox`] allows you to "derive" [`StrongBox`]es for
/// different uses from a single "root" [`StemStrongBox`].
///
/// Let us say, for instance, that you have a typical web application.  You want to keep
/// session data in cookies, but that needs to be encrypted to prevent disclosure and
/// tampering.  You also have to encrypt the state data that you send to your OAuth providers,
/// and you have a couple of database fields that are *super* sensitive, that you'd like to
/// encrypt.
///
/// Traditionally, you'd need to have a set of keys for each of those uses -- which is an absolute pain.
/// However, with the [`StemStrongBox`], you only need to manage one set of keys (the current
/// encryption key, and any previous decryption keys that old data might still be encrypted
/// under), and the other keys can all be *derived* from that one "root" set of keys.
///
/// We might have a "key hierarchy" that looks something like this:
///
/// ```text
///                              +--------+
///                              |  root  |
///                              +--------+
///                                /  |  \
///                              /    |    \
///                            /      |      \
///                          /        |        \
///                        /          |          \
///                +=========+    +-------+    +=========+
///                | cookies |    |  DB   |    |  OAuth  |
///                +=========+    +-------+    +=========+
///                                 /   \
///                               /       \
///                             /           \
///                           /               \
///                     +----------+      +-----------+
///                     |  table1  |      |   table2  |
///                     +----------+      +-----------+
///                       /                 /       \
///                     /                 /           \
///                   /                 /               \
///                 /                 /                   \
///             +===========+    +===========+    +===========+
///             | sensitive |    | sensitive |    | sensitive |
///             |  column A |    |  column B |    |  column C |
///             +===========+    +===========+    +===========+
/// ```
///
/// In the above diagram, the boxes with `---` at top and bottom are [`StemStrongBox`]es, from
/// which you can derive other StrongBoxes (any of [`StemStrongBox`], [`StaticStrongBox`], or [``RotatingStrongBox`]).
/// The boxes with `===` at top and bottom are regular [`StrongBox`]es, and are the ones we use to
/// do cryptography.
///
/// You deliberately cannot have a kind of [`StrongBox`] that can both perform encryption and key
/// derivation, because it is a terrible idea, security wise, to use the same key for different
/// purposes.  Through the power of Rust's type system, we can enforce that.
///
/// # Example
///
/// This is how you might setup the above "tree" of [`StrongBox`]es.
///
/// ```rust
/// # use strong_box::{Error, StemStrongBox};
/// # use std::time::Duration;
/// # fn main() -> Result<(), Error> {
/// # const WEEKLY: Duration = Duration::from_secs(7 * 24 * 3600);
///
/// // A couple of keys are always useful to have
/// let old_key = strong_box::generate_key();
/// let new_key = strong_box::generate_key();
///
/// // This is the basis of all our other boxes
/// let root = StemStrongBox::new(new_key.clone(), [old_key, new_key]);
///
/// // This creates a RotatingStrongBox for secure cookie storage
/// let cookies = root.derive_rotating("cookies", WEEKLY, 52);
///
/// // This is the OAuth provider state box
/// let oauth = root.derive_static("OAuth");
///
/// // Then the great tree of DB column encryption boxes
/// let db = root.derive_stem("DB");
/// let table1 = db.derive_stem("table1");
/// let table2 = db.derive_stem("table2");
///
/// let sensitive_column_a = table1.derive_static("sensitive column A");
/// let sensitive_column_b = table2.derive_static("sensitive column B");
/// let sensitive_column_c = table2.derive_static("sensitive column C");
///
/// // We can now call encrypt/decrypt on any of the boxes created by .derive or .derive_rotating, but
/// // not any of the boxes created by derive_stem, as they are only for further derivation
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct StemStrongBox {
	encryption_key: Key,
	decryption_keys: Vec<Key>,
}

impl StemStrongBox {
	/// Create a new [`StemStrongBox`].
	#[tracing::instrument(level = "debug", skip(enc_key, dec_keys))]
	pub fn new(
		enc_key: impl Into<Key> + Debug,
		dec_keys: impl IntoIterator<Item = impl Into<Key>> + Debug,
	) -> Self {
		Self {
			encryption_key: enc_key.into(),
			decryption_keys: dec_keys.into_iter().map(|k| k.into()).collect(),
		}
	}

	/// Derive a [`StaticStrongBox`] from the keys in this [`StemStrongBox`], for the specified purpose.
	#[tracing::instrument(level = "debug")]
	pub fn derive_static(&self, purpose: impl AsRef<[u8]> + Debug) -> StaticStrongBox {
		let mut context: Vec<u8> = b"derive::".to_vec();
		context.extend_from_slice(purpose.as_ref());
		StaticStrongBox::new(
			kdf::derive_key(&self.encryption_key, &context),
			self.decryption_keys
				.iter()
				.map(|k| kdf::derive_key(k, &context)),
		)
	}

	/// Derive a new [`StemStrongBox`] from the keys in this [`StemStrongBox`], for the specified
	/// purpose.
	#[tracing::instrument(level = "debug")]
	pub fn derive_stem(&self, purpose: impl AsRef<[u8]> + Debug) -> StemStrongBox {
		let mut context: Vec<u8> = b"derive_stem::".to_vec();
		context.extend_from_slice(purpose.as_ref());
		StemStrongBox::new(
			kdf::derive_key(&self.encryption_key, &context),
			self.decryption_keys
				.iter()
				.map(|k| kdf::derive_key(k, &context)),
		)
	}

	/// Derive a new [`RotatingStrongBox`] from the keys in this [`StemStrongBox`], for the specified purpose.
	///
	/// For data that is only valid for a certain period of time, it can be convenient to
	/// automatically "expire" old data by just forgetting the key that encrypted that data.  You
	/// can also avoid the "many encryptions" vulnerability by periodically rotating the key that
	/// is actually used for encryption.
	///
	/// This method creates a [`RotatingStrongBox`], a variant of the regular [`StrongBox`] which
	/// changes the encryption key periodically, and can "look back" a certain number of rotations
	/// to decrypt data that was encrypted with a key produced in a previous rotation period.  You
	/// can always decrypt ciphertexts encrypted in the *current* time period, which is indicated
	/// by a `backtrack` of `0`.
	///
	/// Bear in mind that rotation periods are non-overlapping.  With a `backtrack` of `0`,
	/// a ciphertext created at the very end of a rotation period will only be decryptable for
	/// as little as a nanosecond before the key is expired.  Thus the minimum *practical* value
	/// for `backtrack` is probably `1` in almost all cases.
	///
	/// # Example
	///
	/// Let's say you're encrypting an authentication cookie, and because you're encrypting so many
	/// cookies, you want to rotate the key every week.  However, you allow users to stay logged in
	/// for up to a year, so cookies from up to 52 weeks ago need to still be readable by your
	/// application.
	///
	/// In that case, you could create a [`RotatingStrongBox`] with a "weekly" period, and
	/// use up to 52 previous keys to decrypt the data, like this:
	///
	/// ```rust
	/// # use strong_box::{StemStrongBox, Key};
	/// # use std::time::Duration;
	///
	/// // Seven days, each of 24 hours, each hour with 3,600 seconds
	/// const WEEKLY: Duration = Duration::from_secs(7 * 24 * 3600);
	///
	/// let key = strong_box::generate_key();
	///
	/// let cookie_box = StemStrongBox::new(key, Vec::<Key>::new()).derive_rotating(b"cookies", WEEKLY, 52);
	///
	/// // You can now encrypt/decrypt to your heart's content with the cookie_box
	/// ```
	pub fn derive_rotating(
		&self,
		purpose: impl AsRef<[u8]> + Debug,
		period: Duration,
		backtrack: u16,
	) -> RotatingStrongBox {
		let mut context: Vec<u8> = b"derive_stem::".to_vec();
		context.extend_from_slice(purpose.as_ref());
		RotatingStrongBox::new(
			kdf::derive_key(&self.encryption_key, &context),
			self.decryption_keys
				.iter()
				.map(|k| kdf::derive_key(k, &context))
				.collect(),
			period,
			backtrack,
		)
	}
}
