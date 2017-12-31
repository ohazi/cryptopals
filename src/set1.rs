
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
    let mut result: Vec<u8> = Vec::with_capacity(encoded.len() * 3 / 4);
    let encoded_stripped = encoded.as_bytes()
        .iter()
        .cloned()
        .filter(|letter| match *letter {
            b'\n' => false,
            _ => true,
        })
        .collect::<Vec<u8>>();
    for group in encoded_stripped.chunks(4) {
        if group.len() != 4 {
            return Err("chunk too small!");
        }
        let mut padding: i8 = 0;
        let sextets = group.iter()
            .map(|letter| match *letter {
                c @ b'A'...b'Z' => Ok(c as u8 - 0x41),
                c @ b'a'...b'z' => Ok(c as u8 - 0x61 + 26),
                c @ b'0'...b'9' => Ok(c as u8 - 0x30 + 52),
                b'+' => Ok(62),
                b'/' => Ok(63),
                b'=' => {
                    padding += 1;
                    Ok(0)
                }
                _ => Err("illegal character!"),
            })
            .collect::<Result<Vec<u8>, &'static str>>()?;
        for i in 0..=2 {
            let octet = match i {
                0 => ((sextets[0] & 0x3F) << 2) | ((sextets[1] & 0x30) >> 4),
                1 => ((sextets[1] & 0x0F) << 4) | ((sextets[2] & 0x3C) >> 2),
                2 => ((sextets[2] & 0x03) << 6) | ((sextets[3] & 0x3F) >> 0),
                _ => return Err("too many octets!"),
            };
            if (i as i8) < (3 - padding) {
                result.push(octet);
            }
        }
    }
    return Ok(result);
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

pub fn xor_repeat(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let result = plaintext.iter()
        .zip(key.iter().cycle())
        .map(|pair| match pair {
            (&aa, &bb) => aa ^ bb,
        })
        .collect::<Vec<u8>>();

    return result;
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
            // null
            0 => {}
            // non-printable characters
            1...9 => non_printable_count += 1,
            // newline
            10 => {}
            // more non-printable characters
            11...31 => non_printable_count += 1,
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

extern crate bit_vec;
use self::bit_vec::BitVec;

pub fn hamming_distance(a: &[u8], b: &[u8]) -> Result<u32, &'static str> {
    if a.len() != b.len() {
        return Err("sequences must have same length");
    }
    let result = a.iter()
        .zip(b.iter())
        .map(|(aa, bb)| -> u32 {
            BitVec::from_bytes(&[aa ^ bb]).iter()
                .map(|val| val as u32)
                .sum()})
        .sum();
    return Ok(result);
}

pub fn find_best_single_byte_xor(ciphertext: &[u8]) -> u8 {
    let mut decoded: Vec<(f64, u8, Vec<u8>)> = Vec::with_capacity(256);

    for i in 0..=256 {
        let key: Vec<u8> = vec![i as u8; ciphertext.len()];
        if let Ok(decoded_bytes) = xor(ciphertext, &key) {
            let score = char_freq_score(&decoded_bytes);
            decoded.push((score, i as u8, decoded_bytes));
        }
    }

    decoded.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    let (_, key, _) = decoded[0];
    return key;
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

        //don't want to use a map here, because we'll lose any values with the same score
        //let mut decoded: BTreeMap<u64, (u8, Vec<u8>)> = BTreeMap::new();
        let mut decoded: Vec<(f64, u8, Vec<u8>)> = Vec::with_capacity(256);

        for i in 0..=256 {
            let key: Vec<u8> = vec![i as u8; encoded_bytes.len()];
            if let Ok(decoded_bytes) = super::xor(&encoded_bytes, &key) {
                let score = super::char_freq_score(&decoded_bytes);
                //decoded.insert((score * 1000.0) as u64, (i as u8, decoded_bytes));
                decoded.push((score, i as u8, decoded_bytes));
            }
        }

        decoded.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        //let &(key, ref value) = decoded.values().next().unwrap();
        let (_, key, ref value) = decoded[0];
        assert_eq!(key, 88);
        assert_eq!(
            str::from_utf8(value.as_slice()).unwrap(),
            "Cooking MC's like a pound of bacon"
        );
    }

    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufRead;

    #[test]
    fn detect_single_char_xor() {
        let file = File::open("challenge-data/4.txt").unwrap();
        let reader = BufReader::new(file);

        let mut decoded = BTreeMap::new();

        let mut line_num = 0;
        for line in reader.lines() {
            if let Ok(line) = line {
                let line_bytes = Vec::from_hex(line).unwrap();
                for i in 0..=256 {
                    let key: Vec<u8> = vec![i as u8; line_bytes.len()];
                    if let Ok(decoded_bytes) = super::xor(&line_bytes, &key) {
                        let score = super::char_freq_score(&decoded_bytes);
                        decoded.insert((score * 1000.0) as u64, (line_num, i as u8, decoded_bytes));
                    }
                }
            }
            line_num += 1;
        }

        let mut found = false;
        for (score, &(line, key, ref value)) in decoded.iter() {
            let score: f64 = *score as f64 / 1000.0;
            if score < 100.0 {
                if line == 170 && key == 53 {
                    let value = str::from_utf8(value).unwrap();
                    assert_eq!(value, "Now that the party is jumping\n");
                    found = true;
                }
            }
        }
        assert!(found, "decrypted string not found!");
    }

    #[test]
    fn repeating_key_xor() {
        let plaintext = "Burning 'em, if you ain't quick and nimble\n\
                         I go crazy when I hear a cymbal";
        let key = "ICE";

        let plaintext = plaintext.as_bytes();
        let key = key.as_bytes();

        let ciphertext = super::xor_repeat(&plaintext, &key);
        
        let ciphertext_ref = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226\
                              324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20\
                              283165286326302e27282f";
        let ciphertext_ref = Vec::from_hex(ciphertext_ref).unwrap();

        assert_eq!(ciphertext, ciphertext_ref);
    }

    #[test]
    fn hamming_distance() {
        assert_eq!(
            super::hamming_distance(
                "this is a test".as_bytes(),
                "wokka wokka!!!".as_bytes()).unwrap(),
            37);
    }

    extern crate openssl;
    use self::openssl::symm;
    use self::openssl::symm::Cipher;

    use std::io::prelude::*;

    #[test]
    fn aes_ecb_mode() {
        let mut f = File::open("challenge-data/7.txt").unwrap();
        let mut encoded = String::new();
        f.read_to_string(&mut encoded).unwrap();

        let decoded = super::base64_decode(&encoded).unwrap();

        let plaintext = symm::decrypt(
            Cipher::aes_128_ecb(),
            "YELLOW SUBMARINE".as_bytes(),
            None,
            &decoded).unwrap();
        let plaintext = str::from_utf8(&plaintext).unwrap();

        let mut f = File::open("challenge-data/7_plaintext.txt").unwrap();
        let mut plaintext_ref = String::new();
        f.read_to_string(&mut plaintext_ref).unwrap();

        assert_eq!(plaintext, plaintext_ref);
    }

    #[test]
    fn detect_aes_ecb_mode() {
        let f = File::open("challenge-data/8.txt").unwrap();
        let reader = BufReader::new(f);

        for line in reader.lines() {
            if let Ok(line) = line {
                let line_bytes = Vec::from_hex(line).unwrap();
            }
        }

        panic!("not finished");
    }
}
