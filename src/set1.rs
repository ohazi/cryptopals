
pub fn base64_encode(bytes: &[u8]) -> Result<String, &'static str> {
    let mut result = String::new();
    for group in bytes.chunks(3) {
        let extended = match group.len() {
            1 => [group[0], 0,        0],
            2 => [group[0], group[1], 0],
            3 => [group[0], group[1], group[2]],
            _ => return Err("chunk too large!"),
        };

        for i in 0..=3 {
            let sextet = match i {
                0 =>                               ((extended[0] & 0xFC) >> 2),
                1 => ((extended[0] & 0x03) << 4) | ((extended[1] & 0xF0) >> 4),
                2 => ((extended[1] & 0x0F) << 2) | ((extended[2] & 0xC0) >> 6),
                3 => ((extended[2] & 0x3F) << 0),
                _ => return Err("too many groups!"),
            };

            let symbol: char = match sextet {
                c @ 0...25 => char::from(0x41 + c),
                c @ 26...51 => char::from(0x61 + c - 26),
                c @ 52...61 => char::from(0x30 + c - 52),
                62 => '+',
                63 => '/',
                _ => return Err("too many bits!"),
            };

            if (group.len() as i8) - (i as i8) >= 0 {
                result.push(symbol);
            } else {
                result.push('=');
            }
        }
    }
    return Ok(result);
}

pub fn base64_decode(encoded: &str) -> Result<Vec<u8>, &'static str> {
    Err("not implemented")
}

pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if a.len() != b.len() {
        return Err("buffer size mismatch");
    }

    let result = a.iter()
        .zip(b)
        .map(|pair| match pair {
            (&aa, &bb) => aa ^ bb,
        })
        .collect::<Vec<u8>>();

    return Ok(result);
}

use std::collections::BTreeMap;

pub fn char_freq_score(text: &[u8]) -> f64 {
    let mut non_printable_count = 0;
    let letter_freq: BTreeMap<u8, f64> = btreemap! {
        b'a' => 0.08167,
        b'b' => 0.01492,
        b'c' => 0.02782,
        b'd' => 0.04253,
        b'e' => 0.12702,
        b'f' => 0.02228,
        b'g' => 0.02015,
        b'h' => 0.06094,
        b'i' => 0.06966,
        b'j' => 0.00153,
        b'k' => 0.00772,
        b'l' => 0.04025,
        b'm' => 0.02406,
        b'n' => 0.06749,
        b'o' => 0.07507,
        b'p' => 0.01929,
        b'q' => 0.00095,
        b'r' => 0.05987,
        b's' => 0.06327,
        b't' => 0.09056,
        b'u' => 0.02758,
        b'v' => 0.00978,
        b'w' => 0.02360,
        b'x' => 0.00150,
        b'y' => 0.01974,
        b'z' => 0.00074,
    };

    let mut letter_counts: BTreeMap<u8, u32> = BTreeMap::new();
    for letter in b'a'..=b'z' {
        letter_counts.insert(letter, 0);
    }
    let mut num_letters = 0;
    for letter in text {
        match *letter {
            // non-printable characters
            0...31 => non_printable_count += 1,
            // space
            32 => {}
            // printable symbols, including digits (ascii '!' - '@')
            33...64 => {}
            // upper-case letters
            c @ 65...90 => {
                *letter_counts.get_mut(&(c - 65 + 97)).unwrap() += 1;
                num_letters += 1;
            }
            // more printable symbols (ascii '[' - '`')
            91...96 => {}
            // lower-case letters
            c @ 97...122 => {
                *letter_counts.get_mut(&c).unwrap() += 1;
                num_letters += 1;
            }
            // more printable symbols (ascii '{' - '~')
            123...126 => {}
            // non-printable characters
            _ => non_printable_count += 1,
        }
    }

    if num_letters == 0 {
        return 10000.0 + (non_printable_count as f64 * 500.0);
    }

    let mut chisquared = 0.0;
    for (key, prob) in letter_freq {
        chisquared += (num_letters as f64)
            * ((*letter_counts.get(&key).unwrap() as f64 / num_letters as f64) - prob).powf(2.0)
            / prob;
    }

    return chisquared + (non_printable_count as f64 * 500.0);
}

#[cfg(test)]
mod tests {

    extern crate hex;
    use self::hex::FromHex;

    #[test]
    fn base64_encode() {
        let example_hex = "49276d206b696c6c696e6720796f757220627261696e206c\
                           696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let example_bytes = Vec::from_hex(example_hex).unwrap();

        if let Ok(b64) = super::base64_encode(&example_bytes) {
            assert_eq!(
                b64,
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
            );
        } else {
            panic!();
        }

        let test = "foobar".as_bytes();
        if let Ok(b64) = super::base64_encode(&test) {
            assert_eq!(b64, "Zm9vYmFy");
        } else {
            panic!();
        }
    }

    #[test]
    fn xor() {
        let a = "1c0111001f010100061a024b53535009181c";
        let b = "686974207468652062756c6c277320657965";
        let res = "746865206b696420646f6e277420706c6179";

        let a_bytes = Vec::from_hex(a).unwrap();
        let b_bytes = Vec::from_hex(b).unwrap();
        let res_bytes = Vec::from_hex(res).unwrap();

        match super::xor(&a_bytes, &b_bytes) {
            Ok(r) => assert_eq!(r, res_bytes),
            Err(str) => panic!(str),
        };
    }

    use std::collections::BTreeMap;
    use std::str;

    #[test]
    fn single_byte_xor_cipher() {
        let encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let encoded_bytes = Vec::from_hex(encoded).unwrap();

        let mut decoded: BTreeMap<u64, (u8, Vec<u8>)> = BTreeMap::new();

        for i in 0..=256 {
            let key: Vec<u8> = vec![i as u8; encoded_bytes.len()];
            if let Ok(decoded_bytes) = super::xor(&encoded_bytes, &key) {
                let score = super::char_freq_score(&decoded_bytes);
                decoded.insert((score * 1000.0) as u64, (i as u8, decoded_bytes));
            }
        }

        let &(key, ref value) = decoded.values().next().unwrap();
        assert_eq!(key, 88);
        assert_eq!(
            str::from_utf8(value.as_slice()).unwrap(),
            "Cooking MC's like a pound of bacon"
        );
    }
}
