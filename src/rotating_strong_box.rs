use parking_lot::RwLock;
use secrecy::ExposeSecret as _;
use std::{
	collections::{BTreeMap, BTreeSet},
	fmt::Debug,
	sync::Arc,
	time::Duration,
};

use super::{kdf, Ciphertext, Error, Key, KeyId, StaticStrongBox, StrongBox};

/// A [`StrongBox`] variant that uses a different set of keys for each period of time.
///
/// This box is primarily useful when you're encrypting data that only has to be valid for a
/// relatively short period of time (such as browser cookies and other shortish-lived tokens).  It
/// is particularly beneficial if you could potentially do a lot (ie "many billions") of
/// encryptions over the lifetime of the root keys (because, for various tedious reasons, the
/// risk of a cryptographic break increases based on the number of different encryptions done by
/// one key).
///
/// To use it, you need to specify the "root" encryption and decryption keys, as with any other strong
/// box, but also the [`Duration`] for which key is valid, and also the number of previous
/// time periods which you want to still be able to decrypt.
///
/// The way it works is that time is divided up into periods, each of which has a [`Duration`] of
/// `lifespan`, specified when the [`RotatingStrongBox`] is created.  When an encryption operation is
/// performed, the current period is determined (by looking at the clock and divided by `lifespan`),
/// the encryption key for the current period is derived from the "root" encryption key, and the
/// data is encrypted as normal with that "current encryption key".  So far, so good.
///
/// When a ciphertext is presented for decryption, things get a bit more involved.
/// The [`RotatingStrongBox`] needs to figure out which key to use for decryption, by deriving the
/// decryption keys from the "root" decryption keys specified when the [`RotatingStrongBox`] was
/// created, both for the time period at the time the decryption happens, *as well as* the previous
/// time periods, up to the limit specified by `backtrack`.  If the decryption key for the
/// ciphertext is one of those keys, then decryption happens as normal.  Otherwise, you're out of
/// luck, and the decryption fails.
///
/// Since deriving lots of keys can start to take a little bit of time, the set of decryption keys
/// is cached, and also shared amongst all the clones of a given [`RotatingStrongBox`].  The
/// maximum amount of memory that will be used by the cache (and the amount of time needed to
/// derive all the keys) is determined by the number of separate decryption keys, multiplied by the
/// number of `backtrack` periods allowed.  Each key is relatively small, so don't worry too much,
/// but also don't go "oh, I'll make my key lifespan 30 seconds and cache keys for 10 years"
/// without being ready for a certain amount of bloat.
#[derive(Clone, Debug)]
pub struct RotatingStrongBox {
	// This is just a way for us to test that periods and keys are generated properly,
	// by fiddling with time in unit tests
	time: Clock,

	key_cache: Arc<RwLock<KeyCache>>,
}

// We don't panic while holding the lock
impl std::panic::UnwindSafe for RotatingStrongBox {}

impl RotatingStrongBox {
	#[tracing::instrument(level = "trace")]
	pub(super) fn new(
		enc_key: Key<[u8; 32]>,
		dec_keys: Vec<Key<[u8; 32]>>,
		lifespan: Duration,
		backtrack: u16,
	) -> Self {
		Self {
			#[cfg(not(test))]
			time: Clock,
			#[cfg(test)]
			time: Clock::default(),
			key_cache: Arc::new(RwLock::new(KeyCache {
				lifespan,
				backtrack,
				root_encryption_key: enc_key,
				root_decryption_keys: dec_keys,
				..KeyCache::default()
			})),
		}
	}

	#[tracing::instrument(level = "trace", skip(self, ciphertext))]
	fn try_decrypt_with(&self, ciphertext: &Ciphertext, ctx: &[u8]) -> Result<Vec<u8>, Error> {
		let key_cache = self.key_cache.read_arc();

		if let Some(cached_strongbox) = key_cache.decryptor_cache.get(&ciphertext.key_id) {
			if cached_strongbox.is_expired(self.time.now()) {
				tracing::debug!(key_id=%ciphertext.key_id, "Key expired");
				Err(Error::Decryption)
			} else {
				cached_strongbox
					.strong_box
					.decrypt_ciphertext(ciphertext, ctx)
			}
		} else {
			tracing::debug!(key_id=%ciphertext.key_id, "Key not found");
			Err(Error::Decryption)
		}
	}

	#[cfg(test)]
	fn timewarp(&mut self, secs: i64) {
		self.time.timewarp(secs)
	}
}

impl StrongBox for RotatingStrongBox {
	#[tracing::instrument(level = "debug", skip(plaintext))]
	fn encrypt(
		&self,
		plaintext: impl AsRef<[u8]>,
		ctx: impl AsRef<[u8]> + Debug,
	) -> Result<Vec<u8>, Error> {
		let mut key_cache = self.key_cache.write_arc();
		key_cache
			.current_encryptor(self.time.now())
			.strong_box
			.encrypt(plaintext.as_ref(), ctx.as_ref())
	}

	#[tracing::instrument(level = "debug", skip(ciphertext))]
	fn decrypt(
		&self,
		ciphertext: impl AsRef<[u8]>,
		ctx: impl AsRef<[u8]> + Debug,
	) -> Result<Vec<u8>, Error> {
		fn inner(
			this: &RotatingStrongBox,
			ciphertext: &[u8],
			ctx: &[u8],
		) -> Result<Vec<u8>, Error> {
			let ciphertext = Ciphertext::try_from(ciphertext)?;

			if let Ok(plaintext) = this.try_decrypt_with(&ciphertext, ctx.as_ref()) {
				Ok(plaintext)
			} else {
				let mut key_cache = this.key_cache.write_arc();
				key_cache.refresh_cache(this.time.now());
				// Drop this drop and we'll end up with a deadlock when we call into
				// .try_decrypt_with()
				drop(key_cache);
				this.try_decrypt_with(&ciphertext, ctx.as_ref())
			}
		}
		inner(self, ciphertext.as_ref(), ctx.as_ref())
	}
}

#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Eq, Ord)]
#[repr(transparent)]
struct Timestamp(u64);

impl std::ops::Deref for Timestamp {
	type Target = u64;

	fn deref(&self) -> &u64 {
		&self.0
	}
}

impl std::fmt::Display for Timestamp {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{}", self.0))
	}
}

impl From<u64> for Timestamp {
	fn from(t: u64) -> Self {
		Self(t)
	}
}

impl std::ops::Add<u64> for Timestamp {
	type Output = Timestamp;

	fn add(self, t: u64) -> Self {
		Self(self.0 + t)
	}
}

impl std::ops::Add<i64> for Timestamp {
	type Output = Timestamp;

	fn add(self, t: i64) -> Self {
		Self(self.0.checked_add_signed(t).unwrap())
	}
}

impl std::ops::Add<Timestamp> for Timestamp {
	type Output = Timestamp;

	fn add(self, t: Timestamp) -> Self {
		Self(self.0 + t.0)
	}
}

impl std::ops::Add<Duration> for Timestamp {
	type Output = Timestamp;

	fn add(self, t: Duration) -> Self {
		Self(self.0 + t.as_secs())
	}
}

impl std::ops::Sub<u64> for Timestamp {
	type Output = Timestamp;

	fn sub(self, t: u64) -> Self {
		Self(self.0 - t)
	}
}

impl std::ops::Sub<Timestamp> for Timestamp {
	type Output = Timestamp;

	fn sub(self, t: Timestamp) -> Self {
		Self(self.0 - t.0)
	}
}

impl std::ops::Sub<Duration> for Timestamp {
	type Output = Timestamp;

	fn sub(self, t: Duration) -> Self {
		Self(self.0 - t.as_secs())
	}
}

impl std::ops::Mul<u16> for Timestamp {
	type Output = Timestamp;

	fn mul(self, n: u16) -> Self {
		Self(self.0 * n as u64)
	}
}

impl std::ops::Rem<Duration> for Timestamp {
	type Output = Timestamp;

	fn rem(self, t: Duration) -> Self {
		Self(self.0 % t.as_secs())
	}
}

#[derive(Clone, Debug)]
struct KeyCache {
	lifespan: Duration,
	backtrack: u16,

	root_encryption_key: Key<[u8; 32]>,
	root_decryption_keys: Vec<Key<[u8; 32]>>,

	current_encryptor: CachedStrongBox,

	decryptor_cache: BTreeMap<KeyId, CachedStrongBox>,
	// This is just a way of keeping an ordered set of the
	// cached key IDs and their expiries
	decryptor_validities: BTreeSet<(Timestamp, KeyId)>,
	// Short circuit flag so we don't have to always be deriving keys
	cache_invalid_at: Timestamp,
}

impl Default for KeyCache {
	fn default() -> Self {
		Self {
			lifespan: Duration::from_secs(0),
			backtrack: 0,
			root_encryption_key: Key::new([0; 32]),
			root_decryption_keys: Vec::default(),
			current_encryptor: CachedStrongBox::new([0u8; 32].into(), Timestamp(0)),
			decryptor_cache: BTreeMap::default(),
			decryptor_validities: BTreeSet::default(),
			cache_invalid_at: Timestamp::default(),
		}
	}
}

impl KeyCache {
	fn current_encryptor(&mut self, t: Timestamp) -> &CachedStrongBox {
		if self.current_encryptor.is_expired(t) {
			let current_period = self.period(t);
			self.current_encryptor = CachedStrongBox::new(
				self.derive_key(&self.root_encryption_key, &current_period),
				current_period.invalid_after,
			);
		}

		&self.current_encryptor
	}

	#[tracing::instrument(level = "trace", skip(self))]
	fn derive_key(&self, root_key: &Key<[u8; 32]>, period: &Period) -> Key<[u8; 32]> {
		let mut context = b"rotation::".to_vec();
		context.extend_from_slice(&period.to_bytes());

		kdf::derive_key(root_key, &context)
	}

	#[tracing::instrument(level = "trace", skip(self))]
	fn refresh_cache(&mut self, as_at: Timestamp) {
		if as_at < self.cache_invalid_at {
			return;
		}

		let mut current_period = self.period(as_at);

		// By clearing out all expired keys first, we save memory *and* reduce the chances of the
		// birthday paradox ruining our day
		self.purge_entries_before(current_period.first_valid_at);

		for b in 0..=(self.backtrack) {
			// No point generating keys we've already generated
			let trial_key_id = crate::key_id(
				&self.derive_key(
					self.root_decryption_keys
						.first()
						.expect("caller should have verified we have decryption keys!"),
					&current_period,
				),
			);

			if self.decryptor_cache.contains_key(&trial_key_id) {
				// Since we always start from the "latest" time when adding new keys
				// to the cache, if a key from *this* period is present, then all keys from
				// *previous* periods must be present too
				tracing::debug!("Cache refresh complete due to finding previous generation key");
				return;
			}

			let invalid_after = current_period.invalid_after
				+ (self.backtrack - b) as u64 * self.lifespan.as_secs();

			// Mass key-creation time!
			for key in &self.root_decryption_keys {
				let key = self.derive_key(key, &current_period);
				let key_id = crate::key_id(&key);
				let strongbox = CachedStrongBox::new(key, invalid_after);

				tracing::debug!(%key_id, %invalid_after,
					"Adding key to cache",
				);

				self.decryptor_cache.insert(key_id, strongbox);
				self.decryptor_validities.insert((invalid_after, key_id));
			}

			if let Some(previous_period) = current_period.previous() {
				current_period = previous_period;
			} else {
				// We have reached the dawn of time... how the fuck did that happen?
				tracing::debug!("Epoch reached");
				return;
			}
		}

		tracing::debug!("Cache fully populated");
	}

	#[tracing::instrument(level = "trace", skip(self))]
	fn purge_entries_before(&mut self, t: Timestamp) {
		loop {
			let oldest_entry = self.oldest_cached_decryptor();

			if let Some((expiry, key_id)) = oldest_entry {
				if expiry < t {
					tracing::debug!(%key_id, "Removing expired key");
					self.decryptor_validities.remove(&(expiry, key_id));
					self.decryptor_cache.remove(&key_id);
				} else {
					// Oldest entry is still valid, all done
					return;
				}
			} else {
				// Cache is empty, let's go home
				return;
			}
		}
	}

	#[tracing::instrument(level = "trace", skip(self))]
	fn oldest_cached_decryptor(&self) -> Option<(Timestamp, KeyId)> {
		self.decryptor_validities.first().copied()
	}

	#[tracing::instrument(level = "trace", skip(self))]
	fn period(&self, at: Timestamp) -> Period {
		let first_valid_at = at - (at % self.lifespan);
		let invalid_after = first_valid_at + self.lifespan - 1;

		Period {
			first_valid_at,
			invalid_after,
		}
	}
}

// Represents a "chunk" of time during which a single temporal key is valid.
#[derive(Clone, Debug, PartialEq)]
struct Period {
	first_valid_at: Timestamp,
	invalid_after: Timestamp,
}

impl Period {
	#[tracing::instrument(level = "trace", skip(self))]
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = vec![];

		bytes.extend_from_slice(&self.first_valid_at.to_be_bytes());
		bytes.extend_from_slice(&self.invalid_after.to_be_bytes());

		bytes
	}

	#[tracing::instrument(level = "trace")]
	fn previous(&self) -> Option<Period> {
		self.back_by(1)
	}

	#[tracing::instrument(level = "trace")]
	fn back_by(&self, n: u16) -> Option<Period> {
		let d = (self.invalid_after - self.first_valid_at + 1u64) * n;

		if self.first_valid_at < d {
			// Can't go back before the epoch!
			None
		} else {
			Some(Period {
				first_valid_at: self.first_valid_at - d,
				invalid_after: self.invalid_after - d,
			})
		}
	}
}

#[derive(Clone, Debug)]
struct CachedStrongBox {
	invalid_after: Timestamp,
	strong_box: StaticStrongBox,
}

impl CachedStrongBox {
	#[tracing::instrument(level = "trace", name = "CachedStrongBox::new")]
	fn new(key: Key<[u8; 32]>, invalid_after: Timestamp) -> Self {
		Self {
			invalid_after,
			strong_box: StaticStrongBox::new(*key.expose_secret(), [*key.expose_secret()]),
		}
	}

	#[tracing::instrument(level = "trace")]
	fn is_expired(&self, now: Timestamp) -> bool {
		now > self.invalid_after
	}
}

#[cfg(not(test))]
mod real_clock {
	use super::Timestamp;
	use std::time::{SystemTime, UNIX_EPOCH};

	#[derive(Clone, Debug, Default)]
	pub(super) struct Clock;

	impl Clock {
		#[tracing::instrument(level = "trace")]
		pub(super) fn now(&self) -> Timestamp {
			Timestamp(
				SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_secs(),
			)
		}
	}
}

#[cfg(test)]
mod test_clock {
	use super::Timestamp;
	use std::sync::Arc;

	#[derive(Clone, Debug)]
	pub(super) struct Clock(Arc<Timestamp>);

	impl Default for Clock {
		fn default() -> Self {
			use std::time::{SystemTime, UNIX_EPOCH};
			// Get our initial time from the real world, but then freeze it
			Self(Arc::new(
				SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_secs()
					.into(),
			))
		}
	}

	impl Clock {
		#[tracing::instrument(level = "trace")]
		pub(super) fn now(&self) -> Timestamp {
			*self.0
		}

		#[tracing::instrument(level = "trace")]
		pub(super) fn timewarp(&mut self, secs: i64) {
			if let Some(x) = Arc::<Timestamp>::get_mut(&mut self.0) {
				*x = *x + secs;
			} else {
				panic!("Time has no meaning");
			}
		}
	}
}

#[cfg(not(test))]
use real_clock::Clock;
#[cfg(test)]
use test_clock::Clock;

#[cfg(test)]
mod tests {
	use super::*;
	use crate::generate_key;
	use std::sync::Once;
	use tracing_subscriber::{layer::SubscriberExt as _, registry::Registry};

	static INIT: Once = Once::new();

	fn init() {
		INIT.call_once(|| {
			let layer = tracing_tree::HierarchicalLayer::default()
				.with_writer(tracing_subscriber::fmt::TestWriter::new())
				.with_indent_lines(true)
				.with_indent_amount(2)
				.with_targets(true);

			let sub = Registry::default().with(layer);
			tracing::subscriber::set_global_default(sub).unwrap();
		});
	}

	#[test]
	fn period_calculation() {
		init();
		let kc = KeyCache {
			lifespan: Duration::from_secs(60),
			backtrack: 0,
			..KeyCache::default()
		};

		assert_eq!(
			Period {
				first_valid_at: 0.into(),
				invalid_after: 59.into(),
			},
			kc.period(0.into())
		);
		assert_eq!(
			Period {
				first_valid_at: 0.into(),
				invalid_after: 59.into(),
			},
			kc.period(30.into())
		);
		assert_eq!(
			Period {
				first_valid_at: 0.into(),
				invalid_after: 59.into(),
			},
			kc.period(59.into())
		);
		assert_eq!(
			Period {
				first_valid_at: 60.into(),
				invalid_after: 119.into(),
			},
			kc.period(60.into())
		);
		assert_eq!(
			Period {
				first_valid_at: 1234567860.into(),
				invalid_after: 1234567919.into()
			},
			kc.period(1234567890.into())
		);
	}

	#[test]
	fn previous_period() {
		init();
		let kc = KeyCache {
			lifespan: Duration::from_secs(60),
			backtrack: 0,
			..KeyCache::default()
		};

		assert_eq!(None, kc.period(59.into()).previous());
		assert_eq!(
			Some(Period {
				first_valid_at: 0.into(),
				invalid_after: 59.into(),
			}),
			kc.period(60.into()).previous()
		);
	}

	#[test]
	fn simple_round_trip() {
		init();
		let key = generate_key();
		let rsb = RotatingStrongBox::new(key.into(), vec![key.into()], Duration::new(60, 0), 0);

		let ciphertext = rsb.encrypt(b"hello, world!", b"test").unwrap();

		assert_eq!(
			b"hello, world!".to_vec(),
			rsb.decrypt(&ciphertext, b"test")
				.expect("encryption failed")
		);
	}

	#[test]
	fn context_matters() {
		init();
		let key = generate_key();
		let rsb = RotatingStrongBox::new(key.into(), vec![key.into()], Duration::new(60, 0), 0);

		let ciphertext = rsb.encrypt(b"hello, world!", b"context").unwrap();

		let result = rsb.decrypt(&ciphertext, b"a different context");
		assert!(matches!(result, Err(Error::Decryption)));
	}

	#[test]
	fn static_time_old_key() {
		init();
		let old_key = generate_key();
		let old_rsb = RotatingStrongBox::new(
			old_key.into(),
			Vec::<Key<[u8; 32]>>::new(),
			Duration::new(86400, 0),
			0,
		);

		let ciphertext = old_rsb.encrypt(b"hello, world!", b"test").unwrap();

		let new_key = generate_key();

		let rsb = RotatingStrongBox::new(
			new_key.into(),
			vec![old_key.into()],
			Duration::new(86400, 0),
			0,
		);

		assert_eq!(
			b"hello, world!".to_vec(),
			rsb.decrypt(&ciphertext, b"test")
				.expect("decryption failed")
		);
	}

	#[test]
	fn no_backtracking_allowed() {
		init();

		let key = generate_key();

		let mut rsb = RotatingStrongBox::new(key.into(), vec![key.into()], Duration::new(60, 0), 0);

		// An easy way to get some random input...
		let plaintext = generate_key();
		let ciphertext = rsb.encrypt(&plaintext, b"test").unwrap();

		// Should be able to decrypt what we just encrypted
		tracing::info!("NOW");
		assert_eq!(
			plaintext.to_vec(),
			rsb.decrypt(&ciphertext, b"test")
				.expect("decryption failed")
		);

		// Can't decrypt something we recently encrypted!
		tracing::info!("NOW+1");
		rsb.timewarp(60);
		let result = rsb.decrypt(&ciphertext, b"test");
		assert!(matches!(result, Err::<Vec<u8>, Error>(Error::Decryption)));
	}

	#[test]
	fn the_passing_of_time() {
		init();

		let key = generate_key();

		let mut rsb = RotatingStrongBox::new(key.into(), vec![key.into()], Duration::new(60, 0), 3);

		// An easy way to get some random input...
		let plaintext = generate_key();
		let ciphertext = rsb.encrypt(plaintext, b"test").unwrap();

		// Should be able to decrypt what we just encrypted
		tracing::info!("NOW");
		assert_eq!(
			plaintext.to_vec(),
			rsb.decrypt(&ciphertext, b"test")
				.expect("decryption failed")
		);

		// Now let's move into the fuuuutuuuuuuure

		// Can still decrypt what encrypted one time period ago
		tracing::info!("NOW+1");
		rsb.timewarp(60);
		assert_eq!(
			plaintext.to_vec(),
			rsb.decrypt(&ciphertext, b"test")
				.expect("decryption failed")
		);

		// Two time periods...
		tracing::info!("NOW+2");
		rsb.timewarp(60);
		assert_eq!(
			plaintext.to_vec(),
			rsb.decrypt(&ciphertext, b"test")
				.expect("decryption failed")
		);

		// Even three time periods!
		tracing::info!("NOW+3");
		rsb.timewarp(60);
		assert_eq!(
			plaintext.to_vec(),
			rsb.decrypt(&ciphertext, b"test")
				.expect("decryption failed")
		);

		// But not four time periods... that's *right* out
		tracing::info!("NOW+4");
		rsb.timewarp(60);
		let result = rsb.decrypt(&ciphertext, b"test");
		assert!(matches!(result, Err::<Vec<u8>, Error>(Error::Decryption)));
	}
}
