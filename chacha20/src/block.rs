//! The ChaCha20 block function. Defined in RFC 7539 Section 2.3.
//!
//! <https://tools.ietf.org/html/rfc7539#section-2.3>

use salsa20_core::{CONSTANTS, IV_WORDS, KEY_WORDS, STATE_WORDS};

#[cfg(target_arch = "x86")]
use core::arch::x86::__m128i;
#[cfg(target_arch = "x86")]
use core::arch::x86::_mm_add_epi32;
#[cfg(target_arch = "x86")]
use core::arch::x86::_mm_or_si128;
#[cfg(target_arch = "x86")]
use core::arch::x86::_mm_set_epi32;
#[cfg(target_arch = "x86")]
use core::arch::x86::_mm_shuffle_epi32;
#[cfg(target_arch = "x86")]
use core::arch::x86::_mm_slli_epi32;
#[cfg(target_arch = "x86")]
use core::arch::x86::_mm_slri_epi32;
#[cfg(target_arch = "x86")]
use core::arch::x86::_mm_storeu_si128;
#[cfg(target_arch = "x86")]
use core::arch::x86::_mm_xor_si128;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__m128i;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_add_epi32;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_or_si128;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_set_epi32;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_shuffle_epi32;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_slli_epi32;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_srli_epi32;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_storeu_si128;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_xor_si128;

/// The ChaCha20 block function
///
/// While ChaCha20 is a stream cipher, not a block cipher, its core
/// primitive is a function which acts on a 512-bit block
// TODO(tarcieri): zeroize? need to make sure we're actually copying first
pub(crate) struct Block {
    /// Internal state of the block function
    state: [u32; STATE_WORDS],
}

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"),
          target_feature = "sse"))]
impl Block {
    /// Generate a block
    pub(crate) fn generate(
        key: &[u32; KEY_WORDS],
        iv: [u32; IV_WORDS],
        counter: u64,
    ) -> [u32; STATE_WORDS] {
        unsafe {
            let b0 = _mm_set_epi32(CONSTANTS[3] as i32, CONSTANTS[2] as i32,
                                   CONSTANTS[1] as i32, CONSTANTS[0] as i32);
            let b1 = _mm_set_epi32(key[3] as i32, key[2] as i32,
                                   key[1] as i32, key[0] as i32);
            let b2 = _mm_set_epi32(key[7] as i32, key[6] as i32,
                                   key[5] as i32, key[4] as i32);
            let b3 = _mm_set_epi32(iv[1] as i32, iv[0] as i32,
                                   ((counter >> 32) & 0xffff_ffff) as i32,
                                   (counter & 0xffff_ffff) as i32);

            let (s0, s1, s2, s3) = Self::rounds(b0, b1, b2, b3);

            let f0 = _mm_add_epi32(s0, b0);
            let f1 = _mm_add_epi32(s1, b1);
            let f2 = _mm_add_epi32(s2, b2);
            let f3 = _mm_add_epi32(s3, b3);
            let mut out = [0; STATE_WORDS];
            let p0 = out[0..3].as_mut_ptr();
            let p1 = out[4..7].as_mut_ptr();
            let p2 = out[8..11].as_mut_ptr();
            let p3 = out[12..15].as_mut_ptr();

            _mm_storeu_si128(p0 as *mut __m128i, f0);
            _mm_storeu_si128(p1 as *mut __m128i, f1);
            _mm_storeu_si128(p2 as *mut __m128i, f2);
            _mm_storeu_si128(p3 as *mut __m128i, f3);

            out
        }
    }

    /// Run the 20 rounds (i.e. 10 double rounds) of ChaCha20
    #[inline]
    unsafe fn rounds(s0: __m128i, s1: __m128i, s2: __m128i, s3: __m128i) ->
        (__m128i, __m128i, __m128i, __m128i) {
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);

        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);
        let (s0, s1, s2, s3) = Self::double_round(s0, s1, s2, s3);

        (s0, s1, s2, s3)
    }

    /// Double round function
    #[inline]
    unsafe fn double_round(s0: __m128i, s1: __m128i,
                           s2: __m128i, s3: __m128i) ->
        (__m128i, __m128i, __m128i, __m128i) {

        let s0 = _mm_add_epi32(s0, s1);
        let s3 = _mm_xor_si128(s3, s0);

        let r3 = _mm_srli_epi32(s3, 16);
        let s3 = _mm_slli_epi32(s3, 16);
        let s3 = _mm_or_si128(s3, r3);

        let s2 = _mm_add_epi32(s2, s3);
        let s1 = _mm_xor_si128(s1, s2);

        let r1 = _mm_srli_epi32(s1, 20);
        let s1 = _mm_slli_epi32(s1, 12);
        let s1 = _mm_or_si128(s1, r1);

        let s0 = _mm_add_epi32(s0, s1);
        let s3 = _mm_xor_si128(s3, s0);

        let r3 = _mm_srli_epi32(s3, 24);
        let s3 = _mm_slli_epi32(s3, 8);
        let s3 = _mm_or_si128(s3, r3);

        let s2 = _mm_add_epi32(s2, s3);
        let s1 = _mm_xor_si128(s1, s2);

        let r1 = _mm_srli_epi32(s1, 25);
        let s1 = _mm_slli_epi32(s1, 7);
        let s1 = _mm_or_si128(s1, r1);

        let s1 = _mm_shuffle_epi32(s1, 0x39);
        let s2 = _mm_shuffle_epi32(s2, 0x4e);
        let s3 = _mm_shuffle_epi32(s3, 0x93);

        let s0 = _mm_add_epi32(s0, s1);
        let s3 = _mm_xor_si128(s3, s0);

        let r3 = _mm_srli_epi32(s3, 16);
        let s3 = _mm_slli_epi32(s3, 16);
        let s3 = _mm_or_si128(s3, r3);

        let s2 = _mm_add_epi32(s2, s3);
        let s1 = _mm_xor_si128(s1, s2);

        let r1 = _mm_srli_epi32(s1, 20);
        let s1 = _mm_slli_epi32(s1, 12);
        let s1 = _mm_or_si128(s1, r1);

        let s0 = _mm_add_epi32(s0, s1);
        let s3 = _mm_xor_si128(s3, s0);

        let r3 = _mm_srli_epi32(s3, 24);
        let s3 = _mm_slli_epi32(s3, 8);
        let s3 = _mm_or_si128(s3, r3);

        let s2 = _mm_add_epi32(s2, s3);
        let s1 = _mm_xor_si128(s1, s2);

        let r1 = _mm_srli_epi32(s1, 25);
        let s1 = _mm_slli_epi32(s1, 7);
        let s1 = _mm_or_si128(s1, r1);

        let s1 = _mm_shuffle_epi32(s1, 0x93);
        let s2 = _mm_shuffle_epi32(s2, 0x4e);
        let s3 = _mm_shuffle_epi32(s3, 0x39);

        (s0, s1, s2, s3)
    }
}

#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"),
              target_feature = "sse")))]
impl Block {
    /// Generate a block
    pub(crate) fn generate(
        key: &[u32; KEY_WORDS],
        iv: [u32; IV_WORDS],
        counter: u64,
    ) -> [u32; STATE_WORDS] {
        let mut block = Self {
            state: [
                CONSTANTS[0],
                CONSTANTS[1],
                CONSTANTS[2],
                CONSTANTS[3],
                key[0],
                key[1],
                key[2],
                key[3],
                key[4],
                key[5],
                key[6],
                key[7],
                (counter & 0xffff_ffff) as u32,
                ((counter >> 32) & 0xffff_ffff) as u32,
                iv[0],
                iv[1],
            ],
        };

        block.rounds();
        block.finish(key, iv, counter)
    }

    /// Run the 20 rounds (i.e. 10 double rounds) of ChaCha20
    #[inline]
    fn rounds(&mut self) {
        self.double_round();
        self.double_round();
        self.double_round();
        self.double_round();
        self.double_round();

        self.double_round();
        self.double_round();
        self.double_round();
        self.double_round();
        self.double_round();
    }

    /// Double round function
    #[inline]
    fn double_round(&mut self) {
        let state = &mut self.state;

        state[0] = state[0].wrapping_add(state[4]);
        state[1] = state[1].wrapping_add(state[5]);
        state[2] = state[2].wrapping_add(state[6]);
        state[3] = state[3].wrapping_add(state[7]);

        state[12] ^= state[0];
        state[13] ^= state[1];
        state[14] ^= state[2];
        state[15] ^= state[3];

        state[12] = state[12].rotate_left(16);
        state[13] = state[13].rotate_left(16);
        state[14] = state[14].rotate_left(16);
        state[15] = state[15].rotate_left(16);

        state[8] = state[8].wrapping_add(state[12]);
        state[9] = state[9].wrapping_add(state[13]);
        state[10] = state[10].wrapping_add(state[14]);
        state[11] = state[11].wrapping_add(state[15]);

        state[4] ^= state[8];
        state[5] ^= state[9];
        state[6] ^= state[10];
        state[7] ^= state[11];

        state[4] = state[4].rotate_left(12);
        state[5] = state[5].rotate_left(12);
        state[6] = state[6].rotate_left(12);
        state[7] = state[7].rotate_left(12);

        state[0] = state[0].wrapping_add(state[4]);
        state[1] = state[1].wrapping_add(state[5]);
        state[2] = state[2].wrapping_add(state[6]);
        state[3] = state[3].wrapping_add(state[7]);

        state[12] ^= state[0];
        state[13] ^= state[1];
        state[14] ^= state[2];
        state[15] ^= state[3];

        state[12] = state[12].rotate_left(8);
        state[13] = state[13].rotate_left(8);
        state[14] = state[14].rotate_left(8);
        state[15] = state[15].rotate_left(8);

        state[8] = state[8].wrapping_add(state[12]);
        state[9] = state[9].wrapping_add(state[13]);
        state[10] = state[10].wrapping_add(state[14]);
        state[11] = state[11].wrapping_add(state[15]);

        state[4] ^= state[8];
        state[5] ^= state[9];
        state[6] ^= state[10];
        state[7] ^= state[11];

        state[4] = state[4].rotate_left(7);
        state[5] = state[5].rotate_left(7);
        state[6] = state[6].rotate_left(7);
        state[7] = state[7].rotate_left(7);


        state[0] = state[0].wrapping_add(state[5]);
        state[1] = state[1].wrapping_add(state[6]);
        state[2] = state[2].wrapping_add(state[7]);
        state[3] = state[3].wrapping_add(state[4]);

        state[15] ^= state[0];
        state[12] ^= state[1];
        state[13] ^= state[2];
        state[14] ^= state[3];

        state[15] = state[15].rotate_left(16);
        state[12] = state[12].rotate_left(16);
        state[13] = state[13].rotate_left(16);
        state[14] = state[14].rotate_left(16);

        state[10] = state[10].wrapping_add(state[15]);
        state[11] = state[11].wrapping_add(state[12]);
        state[8] = state[8].wrapping_add(state[13]);
        state[9] = state[9].wrapping_add(state[14]);

        state[5] ^= state[10];
        state[6] ^= state[11];
        state[7] ^= state[8];
        state[4] ^= state[9];

        state[5] = state[5].rotate_left(12);
        state[6] = state[6].rotate_left(12);
        state[7] = state[7].rotate_left(12);
        state[4] = state[4].rotate_left(12);

        state[0] = state[0].wrapping_add(state[5]);
        state[1] = state[1].wrapping_add(state[6]);
        state[2] = state[2].wrapping_add(state[7]);
        state[3] = state[3].wrapping_add(state[4]);

        state[15] ^= state[0];
        state[12] ^= state[1];
        state[13] ^= state[2];
        state[14] ^= state[3];

        state[15] = state[15].rotate_left(8);
        state[12] = state[12].rotate_left(8);
        state[13] = state[13].rotate_left(8);
        state[14] = state[14].rotate_left(8);

        state[10] = state[10].wrapping_add(state[15]);
        state[11] = state[11].wrapping_add(state[12]);
        state[8] = state[8].wrapping_add(state[13]);
        state[9] = state[9].wrapping_add(state[14]);

        state[5] ^= state[10];
        state[6] ^= state[11];
        state[7] ^= state[8];
        state[4] ^= state[9];

        state[5] = state[5].rotate_left(7);
        state[6] = state[6].rotate_left(7);
        state[7] = state[7].rotate_left(7);
        state[4] = state[4].rotate_left(7);
    }

    /// Finish computing a block
    #[inline]
    fn finish(
        self,
        key: &[u32; KEY_WORDS],
        iv: [u32; IV_WORDS],
        counter: u64,
    ) -> [u32; STATE_WORDS] {
        let mut state = self.state;

        state[0] = state[0].wrapping_add(CONSTANTS[0]);
        state[1] = state[1].wrapping_add(CONSTANTS[1]);
        state[2] = state[2].wrapping_add(CONSTANTS[2]);
        state[3] = state[3].wrapping_add(CONSTANTS[3]);
        state[4] = state[4].wrapping_add(key[0]);
        state[5] = state[5].wrapping_add(key[1]);
        state[6] = state[6].wrapping_add(key[2]);
        state[7] = state[7].wrapping_add(key[3]);
        state[8] = state[8].wrapping_add(key[4]);
        state[9] = state[9].wrapping_add(key[5]);
        state[10] = state[10].wrapping_add(key[6]);
        state[11] = state[11].wrapping_add(key[7]);
        state[12] = state[12].wrapping_add((counter & 0xffff_ffff) as u32);
        state[13] = state[13].wrapping_add(((counter >> 32) & 0xffff_ffff) as u32);
        state[14] = state[14].wrapping_add(iv[0]);
        state[15] = state[15].wrapping_add(iv[1]);

        state
    }
}

/// The ChaCha20 quarter round function
#[inline]
pub(crate) fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; 16]) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}
