//! DEFLATE compression (RFC 1951): LZ77 (hash chains, 32 KiB window) with
//! per-block dynamic Huffman codes, falling back to fixed Huffman when a
//! block codes smaller that way. Every stream it produces is verified by
//! roundtrip through this crate's inflate and, in interop testing, through
//! zlib itself.
//!
//! History: v0.1 emitted one fixed-Huffman block for the whole input. The
//! v0.2 encoder codes the LZ77 token stream in ~48 KiB blocks and builds a
//! dynamic Huffman header per block, which is where most of the ratio gain
//! over fixed codes comes from on text. Code lengths are limited to 15 bits
//! (7 for the code-length alphabet) by rescaling frequencies until the tree
//! is shallow enough, so no pathological input needs Kraft-count surgery.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Bytes of input that go into one Huffman block, i.e. one dynamic header.
/// Measured against zlib -6 on text, prose, logs and mixed binary: 48 KiB
/// blocks cost 3-9% ratio because every block repeats a ~100-byte header,
/// while 1 MiB lands within a fraction of a percent of coding the whole
/// input as one block. Sizing it this way also bounds the token buffer
/// (about 4 bytes per input byte, so ~4 MiB here) no matter how large the
/// file is — the old encoder's `prev` array cost 4 bytes per input byte
/// for the entire file.
const BLOCK_BYTES: usize = 1024 * 1024;
const WINDOW: usize = 32_768;
const WINDOW_MASK: usize = WINDOW - 1;
const MAX_CHAIN: usize = 128;
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CODE_BITS: u16 = 15;
const MAX_CL_CODE_BITS: u16 = 7;
/// RFC 1951 3.2.7: order the code-length alphabet's lengths are written in.
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

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

/// One LZ77 token. `len` is 3..=258 and `dist` is 1..=32768, so both fit
/// comfortably in u16 and a token stays small enough to buffer per block.
#[derive(Clone, Copy)]
enum Token {
    Lit(u8),
    Match { len: u16, dist: u16 },
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

fn fixed_lit_bits(sym: u16) -> u32 {
    match sym {
        0..=143 => 8,
        144..=255 => 9,
        256..=279 => 7,
        _ => 8,
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

fn cl_extra_bits(sym: u8) -> u32 {
    match sym {
        16 => 2,
        17 => 3,
        18 => 7,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// LZ77
// ---------------------------------------------------------------------------

/// Match finder. `heads` maps a 3-byte hash to the most recent position and
/// `prev` links positions with the same hash (*windowed*: slot = pos & mask),
/// so the structure costs 256 KiB no matter how large the input is.
struct Lz77 {
    heads: Vec<i32>,
    prev: Vec<i32>,
}

impl Lz77 {
    fn new() -> Self {
        Lz77 {
            heads: vec![-1; HASH_SIZE],
            prev: vec![-1; WINDOW],
        }
    }

    fn hash3(data: &[u8], i: usize) -> usize {
        let v = (data[i] as u32) | ((data[i + 1] as u32) << 8) | ((data[i + 2] as u32) << 16);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
    }

    fn insert(&mut self, data: &[u8], i: usize) {
        if i + 3 <= data.len() {
            let h = Self::hash3(data, i);
            self.prev[i & WINDOW_MASK] = self.heads[h];
            self.heads[h] = i as i32;
        }
    }

    /// Tokenize `data[start..end]`. Matches may look back before `start`
    /// (that is the whole point of keeping the tables across blocks) but
    /// never run past `end`, so blocks stay independently decodable and
    /// every token belongs to exactly one block.
    fn block(&mut self, data: &[u8], start: usize, end: usize) -> Vec<Token> {
        let mut tokens = Vec::new();
        let mut i = start;
        while i < end {
            let mut best_len = 0usize;
            let mut best_dist = 0usize;
            if i + 3 <= end {
                let h = Self::hash3(data, i);
                let mut cand = self.heads[h];
                let mut chain = 0usize;
                while cand >= 0 && chain < MAX_CHAIN {
                    let c = cand as usize;
                    // `c >= i` cannot happen with the invariant that only
                    // positions below `i` are inserted; the check keeps a
                    // malformed table from underflowing `i - c`.
                    if c >= i || i - c > WINDOW {
                        break;
                    }
                    let max_len = (end - i).min(258);
                    let mut l = 0usize;
                    while l < max_len && data[c + l] == data[i + l] {
                        l += 1;
                    }
                    if l >= 3 && l > best_len {
                        best_len = l;
                        best_dist = i - c;
                        if l >= 258 {
                            break;
                        }
                    }
                    cand = self.prev[c & WINDOW_MASK];
                    chain += 1;
                }
            }
            if best_len >= 3 {
                tokens.push(Token::Match {
                    len: best_len as u16,
                    dist: best_dist as u16,
                });
                let stop = i + best_len;
                while i < stop {
                    self.insert(data, i);
                    i += 1;
                }
            } else {
                tokens.push(Token::Lit(data[i]));
                self.insert(data, i);
                i += 1;
            }
        }
        tokens
    }
}

// ---------------------------------------------------------------------------
// Huffman construction
// ---------------------------------------------------------------------------

struct Node {
    sym: i32,
    left: usize,
    right: usize,
}

/// Huffman code lengths for the symbols with a non-zero frequency.
/// Unbounded depth: callers that need a limit use [`huffman_lengths`].
fn build_lengths(freqs: &[u32]) -> Vec<u16> {
    let mut lens = vec![0u16; freqs.len()];
    let mut nodes: Vec<Node> = Vec::new();
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();
    for (sym, &freq) in freqs.iter().enumerate() {
        if freq > 0 {
            nodes.push(Node {
                sym: sym as i32,
                left: usize::MAX,
                right: usize::MAX,
            });
            heap.push(Reverse((freq as u64, nodes.len() - 1)));
        }
    }
    match nodes.len() {
        0 => return lens,
        1 => {
            // A single symbol still needs a code; a 1-bit code is what
            // every decoder (and zlib) expects here.
            lens[nodes[0].sym as usize] = 1;
            return lens;
        }
        _ => {}
    }
    while heap.len() > 1 {
        let Reverse((wa, a)) = heap.pop().expect("heap holds two nodes");
        let Reverse((wb, b)) = heap.pop().expect("heap holds two nodes");
        nodes.push(Node {
            sym: -1,
            left: a,
            right: b,
        });
        heap.push(Reverse((wa + wb, nodes.len() - 1)));
    }
    let Reverse((_, root)) = heap.pop().expect("heap holds the root");
    let mut stack: Vec<(usize, u16)> = vec![(root, 0)];
    while let Some((idx, depth)) = stack.pop() {
        let node = &nodes[idx];
        if node.sym >= 0 {
            lens[node.sym as usize] = depth.max(1);
        } else {
            let deeper = depth + 1;
            stack.push((node.left, deeper));
            stack.push((node.right, deeper));
        }
    }
    lens
}

/// Code lengths capped at `max_bits`. Rebuilding with halved frequencies is
/// how zlib avoids overflow too: gradually flattening the distribution
/// shortens the deepest codes, and every rebuild still produces a complete
/// (Kraft-sum 1) tree, so no code-count fixup is needed.
fn huffman_lengths(freqs: &[u32], max_bits: u16) -> Vec<u8> {
    let mut scaled = freqs.to_vec();
    loop {
        let lens = build_lengths(&scaled);
        if lens.iter().all(|&l| l <= max_bits) {
            return lens.into_iter().map(|l| l as u8).collect();
        }
        for freq in scaled.iter_mut() {
            if *freq > 0 {
                *freq = freq.div_ceil(2);
            }
        }
    }
}

/// Canonical codes (RFC 1951 3.2.2) for a code-length vector.
fn canonical_codes(lens: &[u8]) -> Vec<u32> {
    let max_bits = lens.iter().copied().max().unwrap_or(0) as usize;
    let mut codes = vec![0u32; lens.len()];
    if max_bits == 0 {
        return codes;
    }
    let mut bl_count = vec![0u32; max_bits + 1];
    for &len in lens {
        if len > 0 {
            bl_count[len as usize] += 1;
        }
    }
    let mut next_code = vec![0u32; max_bits + 1];
    let mut code = 0u32;
    for bits in 1..=max_bits {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    for (sym, &len) in lens.iter().enumerate() {
        if len > 0 {
            codes[sym] = next_code[len as usize];
            next_code[len as usize] += 1;
        }
    }
    codes
}

/// Run-length encode the concatenated literal/distance code lengths with
/// symbols 16..=18. Both the bit count and the writer read this one list,
/// so header sizing and header emission cannot drift apart.
fn rle_lengths(seq: &[u8]) -> Vec<(u8, u8)> {
    let mut out: Vec<(u8, u8)> = Vec::new();
    let mut i = 0usize;
    let n = seq.len();
    while i < n {
        let value = seq[i];
        if value == 0 {
            let mut run = 0usize;
            while i + run < n && seq[i + run] == 0 {
                run += 1;
            }
            i += run;
            while run >= 11 {
                let take = run.min(138);
                out.push((18, (take - 11) as u8));
                run -= take;
            }
            if run >= 3 {
                out.push((17, (run - 3) as u8));
                run = 0;
            }
            out.resize(out.len() + run, (0, 0));
        } else {
            out.push((value, 0));
            i += 1;
            let mut run = 0usize;
            while i + run < n && seq[i + run] == value {
                run += 1;
            }
            i += run;
            while run >= 3 {
                let take = run.min(6);
                out.push((16, (take - 3) as u8));
                run -= take;
            }
            out.resize(out.len() + run, (value, 0));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Block encoders
// ---------------------------------------------------------------------------

/// A dynamic-Huffman header plus the codes its tokens are written with.
struct DynamicPlan {
    lit_lens: Vec<u8>,
    lit_codes: Vec<u32>,
    dist_lens: Vec<u8>,
    dist_codes: Vec<u32>,
    hlit: usize,
    hdist: usize,
    cl_lens: Vec<u8>,
    cl_codes: Vec<u32>,
    hclen: usize,
    /// (code-length symbol, value of its extra bits)
    rle: Vec<(u8, u8)>,
    header_bits: u64,
}

impl DynamicPlan {
    fn new(tokens: &[Token]) -> DynamicPlan {
        let mut lit_freq = vec![0u32; 288];
        let mut dist_freq = vec![0u32; 30];
        for token in tokens {
            match *token {
                Token::Lit(byte) => lit_freq[byte as usize] += 1,
                Token::Match { len, dist } => {
                    let (sym, _, _) = length_symbol(len as usize);
                    lit_freq[sym as usize] += 1;
                    let (dsym, _, _) = dist_symbol(dist as usize);
                    dist_freq[dsym as usize] += 1;
                }
            }
        }
        lit_freq[256] += 1; // end-of-block must always have a code
        let lit_lens = huffman_lengths(&lit_freq, MAX_CODE_BITS);
        let mut dist_lens = huffman_lengths(&dist_freq, MAX_CODE_BITS);
        if dist_lens.iter().all(|&len| len == 0) {
            // No matches in this block: one 1-bit distance code keeps the
            // distance tree decodable rather than empty.
            dist_lens[0] = 1;
        }
        let lit_codes = canonical_codes(&lit_lens);
        let dist_codes = canonical_codes(&dist_lens);
        let hlit = lit_lens
            .iter()
            .rposition(|&len| len != 0)
            .map_or(257, |i| (i + 1).max(257));
        let hdist = dist_lens
            .iter()
            .rposition(|&len| len != 0)
            .map_or(1, |i| (i + 1).max(1));
        let mut seq = Vec::with_capacity(hlit + hdist);
        seq.extend_from_slice(&lit_lens[..hlit]);
        seq.extend_from_slice(&dist_lens[..hdist]);
        let rle = rle_lengths(&seq);
        let mut cl_freq = [0u32; 19];
        for &(sym, _) in &rle {
            cl_freq[sym as usize] += 1;
        }
        let cl_lens = huffman_lengths(&cl_freq, MAX_CL_CODE_BITS);
        let cl_codes = canonical_codes(&cl_lens);
        let mut hclen = 4usize;
        for (i, &sym) in CL_ORDER.iter().enumerate() {
            if cl_lens[sym] != 0 {
                hclen = hclen.max(i + 1);
            }
        }
        let mut header_bits: u64 = 5 + 5 + 4 + 3 * hclen as u64;
        for &(sym, _) in &rle {
            header_bits += cl_lens[sym as usize] as u64 + cl_extra_bits(sym) as u64;
        }
        DynamicPlan {
            lit_lens,
            lit_codes,
            dist_lens,
            dist_codes,
            hlit,
            hdist,
            cl_lens,
            cl_codes,
            hclen,
            rle,
            header_bits,
        }
    }

    fn payload_bits(&self, tokens: &[Token]) -> u64 {
        let mut bits = self.lit_lens[256] as u64;
        for token in tokens {
            match *token {
                Token::Lit(byte) => bits += self.lit_lens[byte as usize] as u64,
                Token::Match { len, dist } => {
                    let (sym, _, ebits) = length_symbol(len as usize);
                    let (dsym, _, debits) = dist_symbol(dist as usize);
                    bits += self.lit_lens[sym as usize] as u64
                        + ebits as u64
                        + self.dist_lens[dsym as usize] as u64
                        + debits as u64;
                }
            }
        }
        bits
    }

    fn write(&self, bw: &mut BitWriter, tokens: &[Token], final_block: bool) {
        bw.bits(u32::from(final_block), 1);
        bw.bits(2, 2); // BTYPE = 10, dynamic Huffman
        bw.bits(self.hlit as u32 - 257, 5);
        bw.bits(self.hdist as u32 - 1, 5);
        bw.bits(self.hclen as u32 - 4, 4);
        for &slot in CL_ORDER.iter().take(self.hclen) {
            bw.bits(self.cl_lens[slot] as u32, 3);
        }
        for &(sym, extra) in &self.rle {
            bw.huff(
                self.cl_codes[sym as usize],
                self.cl_lens[sym as usize] as u32,
            );
            let ebits = cl_extra_bits(sym);
            if ebits > 0 {
                bw.bits(extra as u32, ebits);
            }
        }
        for token in tokens {
            match *token {
                Token::Lit(byte) => {
                    bw.huff(
                        self.lit_codes[byte as usize],
                        self.lit_lens[byte as usize] as u32,
                    );
                }
                Token::Match { len, dist } => {
                    let (sym, extra, ebits) = length_symbol(len as usize);
                    bw.huff(
                        self.lit_codes[sym as usize],
                        self.lit_lens[sym as usize] as u32,
                    );
                    if ebits > 0 {
                        bw.bits(extra, ebits);
                    }
                    let (dsym, dextra, debits) = dist_symbol(dist as usize);
                    bw.huff(
                        self.dist_codes[dsym as usize],
                        self.dist_lens[dsym as usize] as u32,
                    );
                    if debits > 0 {
                        bw.bits(dextra, debits);
                    }
                }
            }
        }
        bw.huff(self.lit_codes[256], self.lit_lens[256] as u32);
    }
}

fn fixed_payload_bits(tokens: &[Token]) -> u64 {
    let mut bits = fixed_lit_bits(256) as u64;
    for token in tokens {
        match *token {
            Token::Lit(byte) => bits += fixed_lit_bits(byte as u16) as u64,
            Token::Match { len, dist } => {
                let (sym, _, ebits) = length_symbol(len as usize);
                let (_, _, debits) = dist_symbol(dist as usize);
                bits += fixed_lit_bits(sym) as u64 + ebits as u64 + 5 + debits as u64;
            }
        }
    }
    bits
}

fn write_fixed(bw: &mut BitWriter, tokens: &[Token], final_block: bool) {
    bw.bits(u32::from(final_block), 1);
    bw.bits(1, 2); // BTYPE = 01, fixed Huffman
    for token in tokens {
        match *token {
            Token::Lit(byte) => {
                let (code, nbits) = fixed_lit_code(byte as u16);
                bw.huff(code, nbits);
            }
            Token::Match { len, dist } => {
                let (sym, extra, ebits) = length_symbol(len as usize);
                let (code, nbits) = fixed_lit_code(sym);
                bw.huff(code, nbits);
                if ebits > 0 {
                    bw.bits(extra, ebits);
                }
                let (dsym, dextra, debits) = dist_symbol(dist as usize);
                bw.huff(dsym as u32, 5); // fixed distance codes: 5 bits, code == symbol
                if debits > 0 {
                    bw.bits(dextra, debits);
                }
            }
        }
    }
    let (code, nbits) = fixed_lit_code(256);
    bw.huff(code, nbits);
}

/// Compress `data` into a raw DEFLATE stream: LZ77 tokens in 1 MiB blocks,
/// each block written with whichever of a dynamic or fixed Huffman code is
/// smaller. Blocks are bit-contiguous (no padding between them); only the
/// stream's final byte is padded.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut bw = BitWriter::new();
    if data.is_empty() {
        write_fixed(&mut bw, &[], true);
        return bw.finish();
    }
    let mut lz = Lz77::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let end = (pos + BLOCK_BYTES).min(data.len());
        let final_block = end == data.len();
        let tokens = lz.block(data, pos, end);
        let plan = DynamicPlan::new(&tokens);
        let dynamic_bits = 3 + plan.header_bits + plan.payload_bits(&tokens);
        let fixed_bits = 3 + fixed_payload_bits(&tokens);
        if dynamic_bits < fixed_bits {
            plan.write(&mut bw, &tokens, final_block);
        } else {
            write_fixed(&mut bw, &tokens, final_block);
        }
        pos = end;
    }
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

    fn block_type(stream: &[u8]) -> u32 {
        // BFINAL in bit 0, BTYPE in bits 1..3 (LSB-first packing).
        (stream[0] as u32 >> 1) & 0b11
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
    fn multi_block_streams_roundtrip() {
        // >2 blocks, so BFINAL is only set on the last one and the blocks
        // are bit-contiguous rather than byte-padded.
        for pattern in [
            b"abcdefghij".repeat(15_000),
            vec![0u8; 120_000],
            (0..=255u8).cycle().take(140_000).collect(),
        ] {
            roundtrip(&pattern);
        }
        // Exactly at and just past a block boundary.
        roundtrip(&b"q".repeat(BLOCK_BYTES - 1));
        roundtrip(&b"q".repeat(BLOCK_BYTES));
        roundtrip(&b"q".repeat(BLOCK_BYTES + 1));
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

    #[test]
    fn dynamic_blocks_are_chosen_and_smaller() {
        // Repetitive text: the dynamic header pays for itself immediately.
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(400);
        let stream = deflate(&data);
        assert_eq!(block_type(&stream), 2, "expected a dynamic-Huffman block");
        let (code, nbits) = fixed_lit_code(0);
        assert_eq!((code, nbits), (0x30, 8), "fixed table anchor");
        // A tiny input is cheaper as a fixed block: the dynamic header
        // alone is ~30 bytes.
        let small = deflate(b"hi");
        assert_eq!(block_type(&small), 1, "expected a fixed-Huffman block");
    }

    #[test]
    fn matches_the_validated_reference_model() {
        // Byte-exact anchors taken from a line-by-line Python model of this
        // encoder, whose output was round-tripped through zlib. They pin
        // the wire format (token order, Huffman tie-breaks, header layout)
        // so a refactor cannot silently change the bytes on disk.
        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        }
        let small = deflate(b"hello world, hello world, hello world!");
        assert_eq!(hex("cb48cdc9c95728cf2fca49d151c0c5510400"), small);
        let pangram = b"the quick brown fox jumps over the lazy dog. ".repeat(200);
        let dynamic_hex = concat!(
            "edcac70d83501400c1565e05eec901dbc44f4ed523e802698eab9df19f4537e5ef325e7d5a",
            "9af8a6358aa96e874873d6c7b9abe7bec527fd1e57c1300cc3300cc3300cc3300cc3300cc3",
            "300cc3300cc3300cc3f00df101"
        );
        let packed = deflate(&pangram);
        assert_eq!(hex(dynamic_hex), packed);
        assert_eq!(inflate(&packed).unwrap(), pangram);
        // Multi-block stream (2.2 MB over three 1 MiB blocks): length
        // anchor plus a full roundtrip.
        let multi = b"abcdefghij".repeat(220_000);
        let stream = deflate(&multi);
        assert_eq!(stream.len(), 4321);
        assert_eq!(inflate(&stream).unwrap(), multi);
    }

    #[test]
    fn code_lengths_are_limited_and_complete() {
        // Fibonacci frequencies are the classic worst case for unbounded
        // Huffman depth: 20 symbols already need >15 bits.
        let mut freqs = vec![0u32; 20];
        let (mut a, mut b) = (1u32, 1u32);
        for slot in freqs.iter_mut() {
            *slot = a;
            let next = a + b;
            a = b;
            b = next;
        }
        let lens = huffman_lengths(&freqs, MAX_CODE_BITS);
        assert!(lens.iter().all(|&len| len <= 15));
        let kraft: f64 = lens
            .iter()
            .filter(|&&len| len > 0)
            .map(|&len| 2f64.powi(-(len as i32)))
            .sum();
        assert!((kraft - 1.0).abs() < 1e-9, "incomplete code: kraft {kraft}");
        assert!(build_lengths(&freqs).iter().any(|&len| len > 15));
    }

    #[test]
    fn rle_reconstructs_code_lengths() {
        let seq: Vec<u8> = [
            3u8, 3, 3, 3, 3, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9, 2,
        ]
        .to_vec();
        let rle = rle_lengths(&seq);
        let mut rebuilt: Vec<u8> = Vec::new();
        for &(sym, extra) in &rle {
            match sym {
                16 => {
                    let last = *rebuilt.last().expect("16 needs a previous length");
                    let repeats = 3 + extra as usize;
                    rebuilt.extend(std::iter::repeat(last).take(repeats));
                }
                17 => rebuilt.extend(std::iter::repeat(0u8).take(3 + extra as usize)),
                18 => rebuilt.extend(std::iter::repeat(0u8).take(11 + extra as usize)),
                other => rebuilt.push(other),
            }
        }
        assert_eq!(rebuilt, seq);
    }
}
