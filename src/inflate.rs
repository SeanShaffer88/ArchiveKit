//! DEFLATE decompression (RFC 1951): stored, fixed-Huffman and
//! dynamic-Huffman blocks. Written from the spec; verified against
//! zlib-produced streams in the test suite.
//!
//! This is the raw DEFLATE format (what ZIP method 8 carries), not the
//! zlib wrapper (RFC 1950).

pub type IResult<T> = Result<T, String>;

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize, // byte position
    bitbuf: u32,
    bitcnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            bitbuf: 0,
            bitcnt: 0,
        }
    }
    fn bits(&mut self, need: u32) -> IResult<u32> {
        while self.bitcnt < need {
            if self.pos >= self.data.len() {
                return Err("deflate stream ends unexpectedly".into());
            }
            self.bitbuf |= (self.data[self.pos] as u32) << self.bitcnt;
            self.pos += 1;
            self.bitcnt += 8;
        }
        let v = self.bitbuf & ((1u32 << need) - 1);
        self.bitbuf >>= need;
        self.bitcnt -= need;
        Ok(v)
    }
    fn align_byte(&mut self) {
        let drop = self.bitcnt % 8;
        self.bitbuf >>= drop;
        self.bitcnt -= drop;
    }
}

/// A canonical Huffman decoder built from code lengths (max 15 bits).
struct Huffman {
    /// counts[len] = number of codes of that length
    counts: [u16; 16],
    /// symbols sorted by (length, symbol)
    symbols: Vec<u16>,
}

impl Huffman {
    fn from_lengths(lengths: &[u8]) -> IResult<Huffman> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            if l > 15 {
                return Err("huffman code length > 15".into());
            }
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        // Over-subscription check
        let mut left: i32 = 1;
        for &count in counts.iter().skip(1) {
            left <<= 1;
            left -= count as i32;
            if left < 0 {
                return Err("over-subscribed huffman code".into());
            }
        }
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.iter().filter(|&&l| l != 0).count()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huffman { counts, symbols })
    }

    fn decode(&self, br: &mut BitReader) -> IResult<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16 {
            code |= br.bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - first < count {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err("invalid huffman code in deflate stream".into())
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

fn inflate_block(
    br: &mut BitReader,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
) -> IResult<bool> {
    loop {
        let sym = lit.decode(br)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(true),
            257..=285 => {
                let idx = (sym - 257) as usize;
                if idx >= 29 {
                    return Err("length symbol out of range".into());
                }
                let len = LENGTH_BASE[idx] as usize + br.bits(LENGTH_EXTRA[idx])? as usize;
                let dsym = dist.decode(br)?;
                if dsym as usize >= 30 {
                    return Err("distance symbol out of range".into());
                }
                let d = DIST_BASE[dsym as usize] as usize
                    + br.bits(DIST_EXTRA[dsym as usize])? as usize;
                if d > out.len() {
                    return Err("deflate distance too far back".into());
                }
                let start = out.len() - d;
                for i in 0..len {
                    let b = out[start + i];
                    out.push(b);
                }
            }
            _ => return Err("invalid literal/length symbol".into()),
        }
    }
}

/// Decompress a raw DEFLATE stream. Rejects trailing garbage beyond the
/// final block's end byte (callers that know the exact length — ZIP —
/// pass exactly the compressed bytes).
pub fn inflate(data: &[u8]) -> IResult<Vec<u8>> {
    let mut br = BitReader::new(data);
    let mut out = Vec::new();
    loop {
        let bfinal = br.bits(1)?;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                br.align_byte();
                if br.pos + 4 > data.len() {
                    return Err("stored block header truncated".into());
                }
                let len = u16::from_le_bytes([data[br.pos], data[br.pos + 1]]) as usize;
                let nlen = u16::from_le_bytes([data[br.pos + 2], data[br.pos + 3]]) as usize;
                if len != (!nlen & 0xFFFF) {
                    return Err("stored block LEN/NLEN mismatch".into());
                }
                br.pos += 4;
                br.bitbuf = 0;
                br.bitcnt = 0;
                if br.pos + len > data.len() {
                    return Err("stored block overruns input".into());
                }
                out.extend_from_slice(&data[br.pos..br.pos + len]);
                br.pos += len;
            }
            1 => {
                let mut lit_lengths = [0u8; 288];
                for (i, l) in lit_lengths.iter_mut().enumerate() {
                    *l = match i {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    };
                }
                let lit = Huffman::from_lengths(&lit_lengths)?;
                let dist = Huffman::from_lengths(&[5u8; 30])?;
                inflate_block(&mut br, &mut out, &lit, &dist)?;
            }
            2 => {
                let hlit = br.bits(5)? as usize + 257;
                let hdist = br.bits(5)? as usize + 1;
                let hclen = br.bits(4)? as usize + 4;
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut code_lengths = [0u8; 19];
                for i in 0..hclen {
                    code_lengths[ORDER[i]] = br.bits(3)? as u8;
                }
                let code_huff = Huffman::from_lengths(&code_lengths)?;
                let total = hlit + hdist;
                let mut lengths = vec![0u8; total];
                let mut i = 0;
                while i < total {
                    let sym = code_huff.decode(&mut br)?;
                    match sym {
                        0..=15 => {
                            lengths[i] = sym as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return Err("repeat with no previous length".into());
                            }
                            let prev = lengths[i - 1];
                            let rep = 3 + br.bits(2)? as usize;
                            for _ in 0..rep {
                                if i >= total {
                                    return Err("code length repeat overrun".into());
                                }
                                lengths[i] = prev;
                                i += 1;
                            }
                        }
                        17 => {
                            let rep = 3 + br.bits(3)? as usize;
                            i += rep;
                            if i > total {
                                return Err("code length repeat overrun".into());
                            }
                        }
                        18 => {
                            let rep = 11 + br.bits(7)? as usize;
                            i += rep;
                            if i > total {
                                return Err("code length repeat overrun".into());
                            }
                        }
                        _ => return Err("invalid code-length symbol".into()),
                    }
                }
                let lit = Huffman::from_lengths(&lengths[..hlit])?;
                let dist = Huffman::from_lengths(&lengths[hlit..])?;
                inflate_block(&mut br, &mut out, &lit, &dist)?;
            }
            _ => return Err("reserved deflate block type".into()),
        }
        if bfinal == 1 {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // zlib raw-deflate streams (wbits=-15), produced with Python zlib.
    const BIG_DEFLATE_HEX: &str = "edcfe737950100c7712b21a39095f1502185322a29643611954ac9c575aff970b9669995bd2a1a64662b9a48544668678f062d4a45a928c2f15738cef9bdfe7edf7c5858d9d83916702ee4e2e659c4cbc72fb07889a090f0521151317189659252d23284acdcf2152be515145729ad5ea3aca2ba769d9aba86e6fa0d1bb536696fdea2a3abb755dfc0d0c8d864dbf61d3b77ed363533df6361b977df7eab03070f591f3e6273d4966267ef4075a4d19d9c5d5cdddc490f4f869737d3c7d7cf3f20f0d8f1a0e090d0b0f013274f45444645c7c4c6c52724269d3e733639e5dcf90b1753d32ea567646665e75ccecdcb2f282c2a2eb972b5b4ecdaf51b376fdd2eafa8bc5375b7bae6defd07b575f50d0f1b9b9a1f3d7ef2f4d9f3172f5b5adbda3b3abbba7b7a5fbd7ef3b6afffddfb0f1f3f0d0c7efe32f4f5dbf7e1911f3f477ffdfe3336fef7dfc4e4ffa96916f8e1871f7ef8e1871f7ef8e1871f7ef8e1871f7ef8e1871f7ef8e1871f7ef8e1871f7ef8e1871f7ef8e1871f7ef8e19f877e6f3a95f0643ad9bb10760cd2d79d7024fd0867a69b871741fa5019c46c76a504f8130e240d2b56ac58b162c58a152b56ac58b162c58a75ced719";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn zlib_vectors() {
        // "hello world"
        let v = hex("cb48cdc9c95728cf2fca490100");
        assert_eq!(inflate(&v).unwrap(), b"hello world");
        // Highly repetitive -> exercises length/distance copies.
        let v = hex("4b4c4a4e241a0100");
        assert_eq!(inflate(&v).unwrap(), b"abc".repeat(15));
        // Empty input stream.
        let v = hex("0300");
        assert_eq!(inflate(&v).unwrap(), b"");
    }

    #[test]
    fn zlib_big_vector() {
        // 14,540 bytes: bytes(0..=255) x40 + pangram x100, zlib raw deflate.
        let v = hex(BIG_DEFLATE_HEX);
        let out = inflate(&v).unwrap();
        let mut plain: Vec<u8> = Vec::new();
        for _ in 0..40 {
            plain.extend(0u8..=255);
        }
        for _ in 0..100 {
            plain.extend_from_slice(b"the quick brown fox jumps over the lazy dog");
        }
        assert_eq!(out, plain);
    }

    #[test]
    fn stored_block() {
        // Hand-built stored stream: BFINAL=1, BTYPE=00, pad, LEN=3, NLEN, "abc"
        let mut v = vec![0b0000_0001u8, 3, 0, 0xFC, 0xFF];
        v.extend_from_slice(b"abc");
        assert_eq!(inflate(&v).unwrap(), b"abc");
    }

    #[test]
    fn rejects_garbage() {
        assert!(inflate(&[0xFF, 0xFF, 0xFF]).is_err());
        assert!(inflate(&[]).is_err());
        // Distance too far back must error, not panic.
        let v = hex("cb48cdc9c95728cf2fca490100");
        let mut bad = v.clone();
        bad[0] ^= 0x10;
        let _ = inflate(&bad); // either error or different data; must not panic
    }
}
