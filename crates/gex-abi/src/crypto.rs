//! The A64 cryptographic extension: AES, SHA-1, SHA-256 and the polynomial
//! multiplies, as the architecture defines them on 128-bit registers.
//!
//! Translated code spills its operands to guest memory and calls
//! [`imports::CRYPTO`](crate::imports::CRYPTO), whose hosts run [`run`]:
//! every arm64 Apple chip has these instructions, so corecrypto uses them
//! without asking.

/// The operations, by the number the translator passes.
pub mod op {
    pub const AESE: u64 = 0;
    pub const AESD: u64 = 1;
    pub const AESMC: u64 = 2;
    pub const AESIMC: u64 = 3;
    pub const SHA1C: u64 = 4;
    pub const SHA1P: u64 = 5;
    pub const SHA1M: u64 = 6;
    pub const SHA1SU0: u64 = 7;
    pub const SHA256H: u64 = 8;
    pub const SHA256H2: u64 = 9;
    pub const SHA256SU1: u64 = 10;
    pub const SHA1H: u64 = 11;
    pub const SHA1SU1: u64 = 12;
    pub const SHA256SU0: u64 = 13;
    pub const PMULL_1Q: u64 = 14;
    pub const PMULL2_1Q: u64 = 15;
    pub const PMULL_8H: u64 = 16;
    pub const PMULL2_8H: u64 = 17;
}

/// The bytes the operands take in the spill area: `d`, `n`, `m`, 16
/// each. The result overwrites `d`'s.
pub const SPILL: usize = 48;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];
type V = [u8; 16];

fn words(v: &V) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (i, x) in w.iter_mut().enumerate() {
        *x = u32::from_le_bytes([v[4 * i], v[4 * i + 1], v[4 * i + 2], v[4 * i + 3]]);
    }
    w
}

fn from_words(w: [u32; 4]) -> V {
    let mut v = [0u8; 16];
    for i in 0..4 {
        v[4 * i..4 * i + 4].copy_from_slice(&w[i].to_le_bytes());
    }
    v
}

fn xor(a: &V, b: &V) -> V {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = a[i] ^ b[i];
    }
    r
}

/// `xtime`: multiply by x in GF(2^8).
fn xt(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xt(a);
        b >>= 1;
    }
    p
}

/// AES's state is column-major: byte `i` is row `i % 4` of column `i / 4`.
fn shift_rows(s: &V, inverse: bool) -> V {
    let mut r = [0u8; 16];
    for c in 0..4 {
        for row in 0..4 {
            let from = if inverse { (c + 4 - row) % 4 } else { (c + row) % 4 };
            r[row + 4 * c] = s[row + 4 * from];
        }
    }
    r
}

fn mix_columns(s: &V, inverse: bool) -> V {
    let k: [u8; 4] = if inverse { [14, 11, 13, 9] } else { [2, 3, 1, 1] };
    let mut r = [0u8; 16];
    for c in 0..4 {
        let col = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        for row in 0..4 {
            let mut v = 0;
            for i in 0..4 {
                v ^= gmul(col[(row + i) % 4], k[i]);
            }
            r[4 * c + row] = v;
        }
    }
    r
}

fn choose(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}
fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

/// SHA1C/SHA1P/SHA1M: four rounds on `abcd` (`x`) and `e` (`y`) with
/// the schedule words `w`.
fn sha1(x: V, y: u32, w: V, f: fn(u32, u32, u32) -> u32) -> V {
    let mut x = words(&x);
    let mut y = y;
    let w = words(&w);
    for e in 0..4 {
        let t = f(x[1], x[2], x[3]);
        y = y.wrapping_add(x[0].rotate_left(5)).wrapping_add(t).wrapping_add(w[e]);
        x[1] = x[1].rotate_left(30);
        // <Y, X> = ROL(Y : X, 32)
        let top = x[3];
        x = [y, x[0], x[1], x[2]];
        y = top;
    }
    from_words(x)
}

fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// SHA256H (part 1, the result is `x`) and SHA256H2 (the result is `y`).
fn sha256(x: V, y: V, w: V, part1: bool) -> V {
    let (mut x, mut y, w) = (words(&x), words(&y), words(&w));
    for e in 0..4 {
        let chs = choose(y[0], y[1], y[2]);
        let maj = majority(x[0], x[1], x[2]);
        let t = y[3].wrapping_add(sigma1(y[0])).wrapping_add(chs).wrapping_add(w[e]);
        x[3] = t.wrapping_add(x[3]);
        y[3] = t.wrapping_add(sigma0(x[0])).wrapping_add(maj);
        // <Y, X> = ROL(Y : X, 32)
        let (x3, y3) = (x[3], y[3]);
        x = [y3, x[0], x[1], x[2]];
        y = [x3, y[0], y[1], y[2]];
    }
    from_words(if part1 { x } else { y })
}

/// Carry-less multiply of two 64-bit polynomials.
fn clmul64(a: u64, b: u64) -> u128 {
    let mut r = 0u128;
    for i in 0..64 {
        if b >> i & 1 != 0 {
            r ^= (a as u128) << i;
        }
    }
    r
}

/// Run operation `op` on `d`, `n` and `m`, giving the new `d`.
pub fn run(op: u64, d: V, n: V, m: V) -> V {
    match op {
        op::AESE => {
            let s = shift_rows(&xor(&d, &n), false);
            s.map(|b| SBOX[b as usize])
        }
        op::AESD => {
            let s = shift_rows(&xor(&d, &n), true);
            s.map(|b| INV_SBOX[b as usize])
        }
        op::AESMC => mix_columns(&n, false),
        op::AESIMC => mix_columns(&n, true),
        op::SHA1C => sha1(d, words(&n)[0], m, choose),
        op::SHA1P => sha1(d, words(&n)[0], m, parity),
        op::SHA1M => sha1(d, words(&n)[0], m, majority),
        op::SHA1SU0 => {
            let (a, b, c) = (words(&d), words(&n), words(&m));
            // n<63:0> : d<127:64>, then EOR d EOR m.
            let t = [a[2], a[3], b[0], b[1]];
            from_words([t[0] ^ a[0] ^ c[0], t[1] ^ a[1] ^ c[1], t[2] ^ a[2] ^ c[2], t[3] ^ a[3] ^ c[3]])
        }
        op::SHA1H => from_words([words(&n)[0].rotate_left(30), 0, 0, 0]),
        op::SHA1SU1 => {
            let (x, y) = (words(&d), words(&n));
            let t = [x[0] ^ y[1], x[1] ^ y[2], x[2] ^ y[3], x[3]];
            let w3 = t[3].rotate_left(1) ^ t[0].rotate_left(2);
            from_words([t[0].rotate_left(1), t[1].rotate_left(1), t[2].rotate_left(1), w3])
        }
        op::SHA256H => sha256(d, n, m, true),
        op::SHA256H2 => sha256(n, d, m, false),
        op::SHA256SU0 => {
            let (a, b) = (words(&d), words(&n));
            let t = [a[1], a[2], a[3], b[0]];
            let s = |x: u32| x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
            from_words([0, 1, 2, 3].map(|e| s(t[e]).wrapping_add(a[e])))
        }
        op::SHA256SU1 => {
            let (a, b, c) = (words(&d), words(&n), words(&m));
            let t0 = [b[1], b[2], b[3], c[0]];
            let s = |x: u32| x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);
            let r0 = s(c[2]).wrapping_add(a[0]).wrapping_add(t0[0]);
            let r1 = s(c[3]).wrapping_add(a[1]).wrapping_add(t0[1]);
            let r2 = s(r0).wrapping_add(a[2]).wrapping_add(t0[2]);
            let r3 = s(r1).wrapping_add(a[3]).wrapping_add(t0[3]);
            from_words([r0, r1, r2, r3])
        }
        op::PMULL_1Q | op::PMULL2_1Q => {
            let half = if op == op::PMULL2_1Q { 8 } else { 0 };
            let a = u64::from_le_bytes(n[half..half + 8].try_into().unwrap());
            let b = u64::from_le_bytes(m[half..half + 8].try_into().unwrap());
            clmul64(a, b).to_le_bytes()
        }
        op::PMULL_8H | op::PMULL2_8H => {
            let half = if op == op::PMULL2_8H { 8 } else { 0 };
            let mut r = [0u8; 16];
            for i in 0..8 {
                let p = clmul64(u64::from(n[half + i]), u64::from(m[half + i])) as u16;
                r[2 * i..2 * i + 2].copy_from_slice(&p.to_le_bytes());
            }
            r
        }
        _ => d,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> V {
        let mut v = [0u8; 16];
        for i in 0..16 {
            v[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        v
    }

    /// FIPS-197 appendix C.1, run the way corecrypto runs AES-128: AESE
    /// then AESMC for nine rounds, a last AESE, then the last round key.
    #[test]
    fn aes128_encrypts_the_fips_example() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let mut rk = [key; 11];
        let mut rcon = 1u8;
        for r in 1..11 {
            let p = rk[r - 1];
            let mut t = [p[13], p[14], p[15], p[12]].map(|b| SBOX[b as usize]);
            t[0] ^= rcon;
            rcon = xt(rcon);
            let mut k = [0u8; 16];
            for i in 0..16 {
                k[i] = p[i] ^ if i < 4 { t[i] } else { k[i - 4] };
            }
            rk[r] = k;
        }
        let mut s = hex("00112233445566778899aabbccddeeff");
        let z = [0u8; 16];
        for r in 0..9 {
            s = run(op::AESE, s, rk[r], z);
            s = run(op::AESMC, z, s, z);
        }
        s = run(op::AESE, s, rk[9], z);
        s = xor(&s, &rk[10]);
        assert_eq!(s, hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
        // And back with the equivalent inverse cipher: AESD and AESIMC,
        // the middle round keys passed through InvMixColumns.
        let mut d = run(op::AESD, s, rk[10], z);
        for r in (1..10).rev() {
            d = run(op::AESIMC, z, d, z);
            d = run(op::AESD, d, run(op::AESIMC, z, rk[r], z), z);
        }
        d = xor(&d, &rk[0]);
        assert_eq!(d, hex("00112233445566778899aabbccddeeff"));
    }

    /// The message block of "abc", padded, as big-endian words.
    fn abc_block() -> [u32; 16] {
        let mut w = [0u32; 16];
        w[0] = 0x6162_6380;
        w[15] = 24;
        w
    }

    /// SHA-256 of "abc" through SHA256H, SHA256H2, SHA256SU0 and SHA256SU1,
    /// as a compression function built on them does it.
    #[test]
    fn sha256_compresses_abc() {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
            0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
            0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        let h0 = [0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        let w = abc_block();
        let mut msg = [0, 4, 8, 12].map(|i| from_words([w[i], w[i + 1], w[i + 2], w[i + 3]]));
        let (mut abcd, mut efgh) = (from_words([h0[0], h0[1], h0[2], h0[3]]), from_words([h0[4], h0[5], h0[6], h0[7]]));
        let z = [0u8; 16];
        for q in 0..16 {
            let kq = from_words([K[4 * q], K[4 * q + 1], K[4 * q + 2], K[4 * q + 3]]);
            let wk = from_words({
                let (a, b) = (words(&msg[q % 4]), words(&kq));
                [0, 1, 2, 3].map(|e| a[e].wrapping_add(b[e]))
            });
            let old = abcd;
            abcd = run(op::SHA256H, abcd, efgh, wk);
            efgh = run(op::SHA256H2, efgh, old, wk);
            if q < 12 {
                let next = run(op::SHA256SU0, msg[q % 4], msg[(q + 1) % 4], z);
                msg[q % 4] = run(op::SHA256SU1, next, msg[(q + 2) % 4], msg[(q + 3) % 4]);
            }
        }
        let (a, e) = (words(&abcd), words(&efgh));
        let h: [u32; 8] = core::array::from_fn(|i| if i < 4 { a[i] } else { e[i - 4] }.wrapping_add(h0[i]));
        assert_eq!(h, [0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad]);
    }

    /// SHA-1 of "abc" through SHA1C/P/M, SHA1H, SHA1SU0 and SHA1SU1.
    #[test]
    fn sha1_compresses_abc() {
        let h0 = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        let k = [0x5a827999u32, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
        let w = abc_block();
        let mut msg = [0, 4, 8, 12].map(|i| from_words([w[i], w[i + 1], w[i + 2], w[i + 3]]));
        let mut abcd = from_words([h0[0], h0[1], h0[2], h0[3]]);
        let mut e = h0[4];
        let z = [0u8; 16];
        for q in 0..20 {
            let kk = k[q / 5];
            let wk = from_words(words(&msg[q % 4]).map(|x| x.wrapping_add(kk)));
            let e_next = words(&run(op::SHA1H, z, abcd, z))[0];
            let ev = from_words([e, 0, 0, 0]);
            abcd = match q / 5 {
                0 => run(op::SHA1C, abcd, ev, wk),
                2 => run(op::SHA1M, abcd, ev, wk),
                _ => run(op::SHA1P, abcd, ev, wk),
            };
            e = e_next;
            if q < 16 {
                let t = run(op::SHA1SU0, msg[q % 4], msg[(q + 1) % 4], msg[(q + 2) % 4]);
                msg[q % 4] = run(op::SHA1SU1, t, msg[(q + 3) % 4], z);
            }
        }
        let a = words(&abcd);
        let h: [u32; 5] = core::array::from_fn(|i| if i < 4 { a[i] } else { e }.wrapping_add(h0[i]));
        assert_eq!(h, [0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d]);
    }

    #[test]
    fn pmull_is_carryless() {
        let mut n = [0u8; 16];
        let mut m = [0u8; 16];
        n[..8].copy_from_slice(&3u64.to_le_bytes());
        m[..8].copy_from_slice(&3u64.to_le_bytes());
        // (x + 1)^2 = x^2 + 1
        assert_eq!(u128::from_le_bytes(run(op::PMULL_1Q, [0; 16], n, m)), 5);
    }
}
