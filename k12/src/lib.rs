//! Experimental pure Rust implementation of the KangarooTwelve
//! cryptographic hash algorithm, based on the reference implementation:
//!
//! <https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/kangaroo_twelve-reference/K12.py>
//!
//! Some optimisations copied from: <https://github.com/RustCrypto/hashes/tree/master/sha3/src>

// Based off this translation originally by Diggory Hardy:
// <https://github.com/dhardy/hash-bench/blob/master/src/k12.rs>

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// TODO(tarcieri): eliminate alloc requirement
#[macro_use]
extern crate alloc;

pub use digest;
pub use sha3;

// TODO(tarcieri): eliminate usage of `Vec`
use alloc::vec::Vec;
use core::{cmp::min, mem};
use digest::{ExtendableOutput, ExtendableOutputReset, HashMarker, Reset, Update, XofReader};

/// The KangarooTwelve extendable-output function (XOF).
#[derive(Debug, Default)]
pub struct KangarooTwelve {
    /// Input to be processed
    // TODO(tarcieri): don't store input in a `Vec`
    buffer: Vec<u8>,

    /// Customization string to apply
    // TODO(tarcieri): don't store customization in a `Vec`
    customization: Vec<u8>,
}

impl KangarooTwelve {
    /// Create a new [`KangarooTwelve`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`KangarooTwelve`] instance with the given customization.
    pub fn new_with_customization(customization: impl AsRef<[u8]>) -> Self {
        Self {
            buffer: Vec::new(),
            customization: customization.as_ref().into(),
        }
    }
}

impl HashMarker for KangarooTwelve {}

impl Update for KangarooTwelve {
    fn update(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }
}

impl ExtendableOutput for KangarooTwelve {
    type Reader = Reader;

    fn finalize_xof(self) -> Self::Reader {
        Reader {
            buffer: self.buffer,
            customization: self.customization,
            finished: false,
        }
    }
}

impl ExtendableOutputReset for KangarooTwelve {
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let mut buffer = vec![];
        let mut customization = vec![];

        mem::swap(&mut self.buffer, &mut buffer);
        mem::swap(&mut self.customization, &mut customization);

        Reader {
            buffer,
            customization,
            finished: false,
        }
    }
}

impl Reset for KangarooTwelve {
    fn reset(&mut self) {
        self.buffer.clear();
    }
}

/// Extensible output reader.
///
/// NOTE: this presently only supports one invocation and will *panic* if
/// [`XofReader::read`] is invoked on it multiple times.
#[derive(Debug, Default)]
pub struct Reader {
    /// Input to be processed
    // TODO(tarcieri): don't store input in a `Vec`
    buffer: Vec<u8>,

    /// Customization string to apply
    // TODO(tarcieri): don't store customization in a `Vec`
    customization: Vec<u8>,

    /// Has the XOF output already been consumed?
    // TODO(tarcieri): allow `XofReader::result` to be called multiple times
    finished: bool,
}

// TODO(tarcieri): factor more of this logic into the `KangarooTwelve` type
impl XofReader for Reader {
    /// Get the resulting output of the function.
    ///
    /// Panics if called multiple times on the same instance (TODO: don't panic!)
    fn read(&mut self, output: &mut [u8]) {
        assert!(
            !self.finished,
            "not yet implemented: multiple XofReader::read invocations unsupported"
        );

        let b = 8192;
        const C: usize = 256;

        let mut slice = Vec::new(); // S
        slice.extend_from_slice(&self.buffer);
        slice.extend_from_slice(&self.customization);
        slice.extend_from_slice(&right_encode(self.customization.len())[..]);

        // === Cut the input string into chunks of b bytes ===
        let n = (slice.len() + b - 1) / b;
        let mut slices = Vec::with_capacity(n); // Si
        for i in 0..n {
            let ub = min((i + 1) * b, slice.len());
            slices.push(&slice[i * b..ub]);
        }

        // TODO(tarcieri): get rid of intermediate output buffer
        if n == 1 {
            // === Process the tree with only a final node ===
            let mut hasher = sha3::TurboShake128::from_core(sha3::TurboShake128Core::new(0x07));
            hasher.update(slices[0]);
            hasher.finalize_xof_into(output);
        } else {
            // === Process the tree with kangaroo hopping ===
            let hasher = sha3::TurboShake128::from_core(sha3::TurboShake128Core::new(0x0B));
            // TODO: in parallel
            let mut intermediate = Vec::with_capacity(n - 1); // CVi
            for i in 0..n - 1 {
                let mut digest = [0u8; C / 8];
                let mut h = hasher.clone();
                h.update(slices[i + 1]);
                h.finalize_xof_into(&mut digest);
                intermediate.push(digest);
            }

            let mut node_star = Vec::new();
            node_star.extend_from_slice(slices[0]);
            node_star.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]);

            #[allow(clippy::needless_range_loop)]
            for i in 0..n - 1 {
                node_star.extend_from_slice(&intermediate[i][..]);
            }

            node_star.extend_from_slice(&right_encode(n - 1));
            node_star.extend_from_slice(b"\xFF\xFF");

            let mut hasher = sha3::TurboShake128::from_core(sha3::TurboShake128Core::new(0x06));
            hasher.update(&node_star[..]);
            hasher.finalize_xof_into(output);
        };

        self.finished = true;
    }
}

fn right_encode(mut x: usize) -> Vec<u8> {
    let mut slice = Vec::new();
    while x > 0 {
        slice.push((x % 256) as u8);
        x /= 256;
    }
    slice.reverse();
    let len = slice.len();
    slice.push(len as u8);
    slice
}
