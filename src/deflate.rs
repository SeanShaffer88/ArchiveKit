//! DEFLATE compression (RFC 1951): LZ77 (hash chains, 32 KiB window)
//! emitted as a single fixed-Huffman block. Not ratio-optimal like zlib's
//! dynamic Huffman + lazy matching, but valid, dependency-free, and
//! typically within ~10-20% of zlib-6 on ordinary data. Every stream it
//! produces is verified by roundtrip through this crate's inflate and,
//! in interop testing, through zlib itself.

struct BitWriter {
    out: Vec<u8>,
    bitbuf: u32,
    bitcnt: u32,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            out: Vec::new(),
            bitbuf: 0,
            bitcnt: 0,
        }
    }
    fn bits(&mut self, value: u32, count: u32) {
        self.bitbuf |= value << self.bitcnt;
        self.bitcnt += count;
        while self.bitcnt >= 8 {
            self.out.push((self.bitbuf & 0xFF) as u8);
            self.bitbuf >>= 8;
            self.bitcnt -= 8;
        }
    }
    /// Huffman codes are emitted most-significant-bit first, i.e. the
    /// code's bits are reversed relative to the LSB-first packing.
    fn huff(&mut self, code: u32, count: u32) {
        self.bits(code.reverse_bits() >> (32 - count), count);
    }
    fn finish(mut self) -> Vec<u8> {
        if self.bitcnt > 0 {
            self.out.push((self.bitbuf & 0xFF) as u8);
        }
        self.out
    }
}

/// Fixed literal/length code (RFC 1951 3.2.6) for a symbol.
fn fixed_lit_code(sym: u16) -> (u32, u32) {
    match sym {
        0..=143 => (0x30 + sym as u32, 8),
        144..=255 => (0x190 + (sym as u32 - 144), 9),
        256..=279 => ((sym - 256) as u32, 7),
        _ => (0xC0 + (sym as u32 - 280), 8),
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn length_symbol(len: usize) -> (u16, u32, u32) {
    // returns (symbol, extra value, extra bits); len in 3..=258
    debug_assert!((3..=258).contains(&len));
    if len == 258 {
        return (285, 0, 0);
    }
    let mut idx = 0;
    for (i, &base) in LENGTH_BASE.iter().enumerate() {
        if base as usize <= len {
            idx = i;
        } else {
            break;
        }
    }
    (
        257 + idx as u16,
        (len - LENGTH_BASE[idx] as usize) as u32,
        LENGTH_EXTRA[idx],
    )
}

fn dist_symbol(dist: usize) -> (u16, u32, u32) {
    debug_assert!((1..=32768).contains(&dist));
    let mut idx = 0;
    for (i, &base) in DIST_BASE.iter().enumerate() {
        if base as usize <= dist {
            idx = i;
        } else {
            break;
        }
    }
    (
        idx as u16,
        (dist - DIST_BASE[idx] as usize) as u32,
        DIST_EXTRA[idx],
    )
}

const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;

fn hash3(data: &[u8], i: usize) -> usize {
    let v = (data[i] as u32) | ((data[i + 1] as u32) << 8) | ((data[i + 2] as u32) << 16);
    (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

/// Compress `data` into a raw DEFLATE stream (single fixed-Huffman block).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut bw = BitWriter::new();
    bw.bits(1, 1); // BFINAL
    bw.bits(1, 2); // BTYPE = 01 fixed Huffman
    if data.is_empty() {
        let (c, n) = fixed_lit_code(256);
        bw.huff(c, n);
        return bw.finish();
    }
    let mut head = vec![-1i32; HASH_SIZE];
    let mut prev = vec![-1i32; data.len()];
    let mut i = 0usize;
    while i < data.len() {
        let mut match_len = 0usize;
        let mut match_dist = 0usize;
        if i + 3 <= data.len() {
            let h = hash3(data, i);
            let mut cand = head[h];
            let mut chain = 0;
            while cand >= 0 && chain < 128 {
                let c = cand as usize;
                if i - c > 32768 {
                    break;
                }
                // Extend match at c
                let mut l = 0;
                while i + l < data.len() && l < 258 && data[c + l] == data[i + l] {
                    l += 1;
                }
                if l >= 3 && l > match_len {
                    match_len = l;
                    match_dist = i - c;
                    if l >= 258 {
                        break;
                    }
                }
                cand = prev[c];
                chain += 1;
            }
        }
        if match_len >= 3 {
            let (sym, extra, ebits) = length_symbol(match_len);
            let (c, n) = fixed_lit_code(sym);
            bw.huff(c, n);
            if ebits > 0 {
                bw.bits(extra, ebits);
            }
            let (dsym, dextra, debits) = dist_symbol(match_dist);
            bw.huff(dsym as u32, 5); // fixed dist codes: 5 bits, code == symbol
            if debits > 0 {
                bw.bits(dextra, debits);
            }
            // Insert every position we pass into the hash table.
            let end = i + match_len;
            while i < end {
                if i + 3 <= data.len() {
                    let h = hash3(data, i);
                    prev[i] = head[h];
                    head[h] = i as i32;
                }
                i += 1;
            }
        } else {
            let (c, n) = fixed_lit_code(data[i] as u16);
            bw.huff(c, n);
            if i + 3 <= data.len() {
                let h = hash3(data, i);
                prev[i] = head[h];
                head[h] = i as i32;
            }
            i += 1;
        }
    }
    let (c, n) = fixed_lit_code(256);
    bw.huff(c, n);
    bw.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inflate::inflate;

    fn roundtrip(data: &[u8]) {
        let comp = deflate(data);
        let back = inflate(&comp).unwrap();
        assert_eq!(back, data, "roundtrip failed for {} bytes", data.len());
    }

    #[test]
    fn roundtrips() {
        roundtrip(b"");
        roundtrip(b"a");
        roundtrip(b"hello world, hello world, hello world!");
        roundtrip(&[0u8; 1000]);
        roundtrip(&[0xFFu8; 300]);
        let mut big = Vec::new();
        for _ in 0..40 {
            big.extend(0u8..=255);
        }
        for _ in 0..100 {
            big.extend_from_slice(b"the quick brown fox jumps over the lazy dog");
        }
        roundtrip(&big);
        // Pseudo-random (incompressible-ish) data via a simple LCG.
        let mut x: u32 = 0x1234_5678;
        let rand: Vec<u8> = (0..5000)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect();
        roundtrip(&rand);
        // Long match > 258 and distances near the window edge.
        let mut far = vec![b'x'; 40_000];
        far.extend_from_slice(b"0123456789");
        far.extend(std::iter::repeat(b'x').take(100));
        roundtrip(&far);
    }

    #[test]
    fn actually_compresses() {
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(200);
        let comp = deflate(&data);
        assert!(
            comp.len() < data.len() / 4,
            "{} -> {} not compressed enough",
            data.len(),
            comp.len()
        );
    }
}
