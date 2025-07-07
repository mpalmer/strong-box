//! Secure symmetric encryption using modern algorithms and affordances.
//!
//! If you want to encrypt something that only someone with the same key can decrypt, and you want
//! the most up-to-date algorithms and security properties (such as Additional Data validation),
//! then StrongBox is for you.
//!
//! A [`StrongBox`] exists to encrypt and decrypt data.  It uses a single key to encrypt all
//! data, and can decrypt data that was previously encrypted with any key in the list.
//!
//! The ability to specify a list of decryption keys allows for periodic key rotation, without
//! losing the ability to decrypt old ciphertexts.  This is important because *every* symmetric
//! cipher scheme is weakened when many plaintexts (in the "billions" range, so it's *usually* OK)
//! are encrypted with the same key, so it's worth rotating your keys now and then.  You simply
//! generate a new key, specify that as your encryption key, and make sure the list of decryption
//! keys includes the new key and all the previous keys that any remaining valid ciphertexts may
//! have been encrypted with.
//!
//! The encryption *context* is used to provide protection against attacks involving
//! substituting one ciphertext for another.  [This Security StackExchange
//! answer](https://security.stackexchange.com/a/179279/167630) is an excellent explanation of
//! why an encryption context is useful.  If for whatever reason you don't have an appropriate
//! context, you can use `b""` as the context, but remember that the same context must be specified
//! for both encryption *and* decryption.
//!
//! # Other Kinds of StrongBoxes
//!
//! If you have multiple different *kinds* of data to encrypt (say, different fields of a
//! database), it's safer (on many fronts) to encrypt the different kinds of data with different
//! keys.  To facilitate that, you can create a [`StemStrongBox`], and "derive" new StrongBoxes
//! that use keys derived from the keys in the [`StemStrongBox`].  This keeps you from having to
//! manage great masses of keys -- instead, just have one set of "root" keys, and derive all the
//! other ones you need.  Of course, you can derive another [`StemStrongBox`] from *that* one, and so
//! on, creating a whole "tree" of [`StrongBox`]es.
//!
//! You can also create a [`RotatingStrongBox`], that automatically rotates its keys according to a
//! fixed schedule, and maintains the ability to decrypt ciphertexts encrypted by keys from a
//! bounded number of previous rotations.
//!
//! Finally, there is the [`SharedStrongBox`], which anyone with a public key can use to encrypt
//! data that only someone with the corresponding private key can decrypt.
mod error;
mod rotating_strong_box;
mod shared_strong_box;
mod static_strong_box;
mod stem_strong_box;
mod strong_box;

pub use ::ciborium;

pub use error::Error;
pub use rotating_strong_box::RotatingStrongBox;
pub use shared_strong_box::{SharedStrongBox, SharedStrongBoxKey};
pub use static_strong_box::StaticStrongBox;
pub use stem_strong_box::StemStrongBox;
pub use strong_box::StrongBox;

use static_strong_box::Ciphertext;

mod kdf;
mod key;
mod key_id;

pub use key::{Key, generate_key};
use key_id::{KeyId, key_id};
