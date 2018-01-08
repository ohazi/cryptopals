use set1;

pub fn pkcs7_pad(data: &[u8], blocksize: u8) -> Result<Vec<u8>, &'static str> {
    if blocksize == 0 {
        return Err("block size cannot be zero");
    }
    let num_blocks = (data.len() + (blocksize as usize)) / blocksize as usize;
    let output_len = num_blocks * blocksize as usize;
    let pad_byte: u8 = (output_len - data.len()) as u8;

    let mut output: Vec<u8> = Vec::with_capacity(output_len);
    output.extend_from_slice(data);
    output.extend(vec![pad_byte; pad_byte as usize]);

    return Ok(output);
}

pub fn pkcs7_unpad(data: &[u8], blocksize: u8) -> Result<&[u8], &'static str> {
    if blocksize == 0 {
        return Err("block size cannot be zero");
    }
    if data.is_empty() {
        return Err("message length cannot be zero");
    }
    if data.len() % blocksize as usize != 0 {
        return Err("message length must be an integer multiple of block size");
    }

    let pad_byte: u8 = *data.last().unwrap();
    if pad_byte > blocksize {
        return Err("found pad byte larger than block size");
    }
    return Ok(data.get(..(data.len() - pad_byte as usize)).unwrap());
}

pub fn pkcs7_unpad_unchecked(data: &[u8], blocksize: u8) -> Result<&[u8], &'static str> {
    let pad_byte: u8 = *data.last().unwrap();
    if pad_byte > blocksize {
        return Err("found pad byte larger than block size");
    }
    if pad_byte as usize > data.len() {
        return Err("found pad byte larger than message size");
    }
    return Ok(data.get(..(data.len() - pad_byte as usize)).unwrap());
}

extern crate openssl;
use self::openssl::symm::{Cipher, Crypter, Mode};

//extern crate hex;
//use self::hex::ToHex;

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if key.len() != 16 {
        return Err("invalid key size");
    }
    if iv.len() != 16 {
        return Err("invalid IV size");
    }

    let plaintext_padded = pkcs7_pad(plaintext, 16).unwrap();

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();

    // We're doing this manually
    crypter.pad(false);

    let mut ciphertext = vec![0; plaintext_padded.len() + 16];
    let mut count = 0;

    let mut xor_block = Vec::with_capacity(16);
    xor_block.extend_from_slice(iv);

    let xor_count = plaintext_padded
        .chunks(16)
        .map(|block| {
            let xor_count = set1::xor_in_place(&mut xor_block, block).unwrap();
            let start = count;
            count += crypter
                .update(&xor_block, ciphertext.get_mut(count..).unwrap())
                .unwrap();
            for (x, c) in xor_block.iter_mut().zip(&ciphertext[start..count]) {
                *x = *c;
            }
            return xor_count;
        })
        .sum::<usize>();

    count += crypter
        .finalize(ciphertext.get_mut(count..).unwrap())
        .unwrap();
    ciphertext.truncate(count);

    if count != xor_count {
        return Err("encrypted block and xor block byte count mismatch");
    }

    return Ok(ciphertext);
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if key.len() != 16 {
        return Err("invalid key size");
    }
    if iv.len() != 16 {
        return Err("invalid IV size");
    }
    if ciphertext.len() % 16 != 0 {
        return Err("invalid ciphertext size");
    }

    let xor_blocks = iv.chunks(16)
        .chain(ciphertext.chunks(16))
        .take(ciphertext.len() / 16);

    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();

    // We're doing this manually
    decrypter.pad(false);

    let mut decrypted: Vec<u8> = vec![0; ciphertext.len() + 16];
    let mut count = 0;

    ciphertext
        .chunks(16)
        .map(|block| {
            count += decrypter
                .update(block, decrypted.get_mut(count..).unwrap())
                .unwrap();
        })
        .count();
    count += decrypter
        .finalize(decrypted.get_mut(count..).unwrap())
        .unwrap();
    decrypted.truncate(count);

    let xor_count = decrypted
        .chunks_mut(16)
        .zip(xor_blocks)
        .map(|(decrypted_block, xor_block)| set1::xor_in_place(decrypted_block, xor_block).unwrap())
        .sum::<usize>();

    if xor_count != count {
        return Err("decrypted block and xor block byte count mismatch");
    }

    let plaintext_unpadded_len = pkcs7_unpad(&decrypted, 16).unwrap().len();
    decrypted.truncate(plaintext_unpadded_len);

    return Ok(decrypted);
}

extern crate rand;
use self::rand::Rng;

use self::openssl::symm;

#[derive(Debug, PartialEq)]
pub enum CipherMode {
    CBC,
    ECB,
    Unknown,
}

pub fn encryption_oracle(input: &[u8]) -> (Vec<u8>, CipherMode) {
    let mut rng = rand::thread_rng();

    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    let mut plaintext: Vec<u8> = Vec::with_capacity(input.len() + 20);

    let prefix_len = rng.gen_range(5, 11);
    let prefix = rng.gen_iter::<u8>().take(prefix_len).collect::<Vec<u8>>();
    plaintext.extend_from_slice(&prefix);

    plaintext.extend_from_slice(input);

    let suffix_len = rng.gen_range(5, 11);
    let suffix = rng.gen_iter::<u8>().take(suffix_len).collect::<Vec<u8>>();
    plaintext.extend_from_slice(&suffix);

    if rng.gen() {
        // cbc mode
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);

        return (
            aes_cbc_encrypt(&key, &iv, &plaintext).unwrap(),
            CipherMode::CBC,
        );
    } else {
        // ecb mode
        return (
            symm::encrypt(Cipher::aes_128_ecb(), &key, None, &plaintext).unwrap(),
            CipherMode::ECB,
        );
    }
}

pub fn detect_ecb_cbc<F>(mut oracle: F) -> CipherMode
where
    F: FnMut(&[u8]) -> Vec<u8>,
{
    let test_input = [0; 256];
    let result = oracle(&test_input);

    let test_blocks = result.chunks(16).skip(1).take(2).collect::<Vec<&[u8]>>();
    if test_blocks[0] == test_blocks[1] {
        return CipherMode::ECB;
    } else {
        return CipherMode::CBC;
    }
}

pub trait Oracle {
    fn oracle(&self, input: &[u8]) -> Vec<u8>;
}

pub struct EcbOracleSimple {
    key: [u8; 16],
}

impl EcbOracleSimple {
    pub fn new() -> EcbOracleSimple {
        let mut rng = rand::thread_rng();

        let mut key = [0; 16];
        rng.fill_bytes(&mut key);
        println!("key: {}", set1::to_hex(&key));

        EcbOracleSimple { key: key }
    }
}

impl Oracle for EcbOracleSimple {
    fn oracle(&self, input: &[u8]) -> Vec<u8> {
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                              aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                              dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                              YnkK";
        let unknown_string = set1::base64_decode(unknown_string).unwrap();

        let mut plaintext = Vec::with_capacity(input.len() + unknown_string.len());
        plaintext.extend_from_slice(input);
        plaintext.extend_from_slice(&unknown_string);

        return symm::encrypt(Cipher::aes_128_ecb(), &self.key, None, &plaintext).unwrap();
    }
}

pub fn byte_at_a_time_ecb_decryption_simple(oracle: &Oracle) -> Result<String, &'static str> {
    // First find block size
    let mut blocksize = 0;
    let mut prev_result = [0; 128];
    for i in 2..128 {
        let mut input = vec![0; 128];
        input[i] = 1;
        let result = oracle.oracle(&input);

        if result[..i - 1] == prev_result[..i - 1] {
            blocksize = i - 1;
            break;
        } else {
            prev_result.copy_from_slice(&result[..128]);
        }
    }

    if blocksize == 0 {
        return Err("could not determine block size");
    }

    match detect_ecb_cbc(|input| oracle.oracle(input)) {
        CipherMode::ECB => {}
        _ => return Err("Oracle doesn't appear to use ECB"),
    }

    let mut decoded: Vec<u8> = Vec::new();

    let padding = vec!['A' as u8; blocksize];
    'decode: for i in 0..500 {
        let block_num = i / blocksize;
        let block_pos = i % blocksize;

        let offset = &padding[block_pos..blocksize - 1];
        assert_eq!(offset.len(), blocksize - 1 - block_pos);
        let oracle_offset = oracle.oracle(offset);

        let mut test = Vec::with_capacity(blocksize);
        if block_num == 0 {
            test.extend_from_slice(offset);
            test.extend_from_slice(&decoded);
        } else {
            test.extend_from_slice(&decoded[decoded.len() - (blocksize - 1)..]);
        }
        assert_eq!(test.len(), blocksize - 1);

        for j in 0..=255 {
            test.push(j);
            let oracle_test = oracle.oracle(&test);
            test.pop();

            if let Some(block) = oracle_offset
                .chunks(blocksize)
                .skip(block_num)
                .take(1)
                .next()
            {
                if block == oracle_test.chunks(blocksize).take(1).next().unwrap() {
                    decoded.push(j);
                    break;
                }
            } else {
                break 'decode;
            }
        }
    }

    let decoded_len = pkcs7_unpad_unchecked(&decoded, blocksize as u8)
        .unwrap()
        .len();
    decoded.truncate(decoded_len);

    return Ok(String::from_utf8(decoded).unwrap());
}

#[cfg(test)]
mod tests {

    use set1;
    use set2;

    #[test]
    fn pkcs7_pad() {
        let test = "YELLOW SUBMARINE".as_bytes();
        let test_pad = set2::pkcs7_pad(test, 20).unwrap();
        assert_eq!(test_pad, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
        assert_eq!(set2::pkcs7_unpad(&test_pad, 20).unwrap(), test);

        let test = "abcd".as_bytes();
        let test_pad = set2::pkcs7_pad(test, 4).unwrap();
        assert_eq!(test_pad, "abcd\x04\x04\x04\x04".as_bytes());
        assert_eq!(set2::pkcs7_unpad(&test_pad, 4).unwrap(), test);
    }

    use std::str;

    use std::fs::File;
    use std::io::prelude::*;

    #[test]
    fn aes_cbc_encrypt() {
        let mut f = File::open("challenge-data/10_plaintext.txt").unwrap();
        let mut plaintext = String::new();
        f.read_to_string(&mut plaintext).unwrap();

        let ciphertext = set2::aes_cbc_encrypt(
            "YELLOW SUBMARINE".as_bytes(),
            &[0 as u8; 16],
            plaintext.as_bytes(),
        ).unwrap();

        let mut f = File::open("challenge-data/10.txt").unwrap();
        let mut ciphertext_ref = String::new();
        f.read_to_string(&mut ciphertext_ref).unwrap();
        let ciphertext_ref = set1::base64_decode(&ciphertext_ref).unwrap();

        assert_eq!(ciphertext, ciphertext_ref);
    }

    #[test]
    fn aes_cbc_decrypt() {
        let mut f = File::open("challenge-data/10.txt").unwrap();
        let mut ciphertext = String::new();
        f.read_to_string(&mut ciphertext).unwrap();

        let ciphertext = set1::base64_decode(&ciphertext).unwrap();

        let plaintext =
            set2::aes_cbc_decrypt("YELLOW SUBMARINE".as_bytes(), &[0 as u8; 16], &ciphertext)
                .unwrap();

        let plaintext = str::from_utf8(&plaintext).unwrap();

        let mut f = File::open("challenge-data/10_plaintext.txt").unwrap();
        let mut plaintext_ref = String::new();
        f.read_to_string(&mut plaintext_ref).unwrap();

        assert_eq!(plaintext, plaintext_ref);
    }

    #[test]
    fn detect_ecb_cbc() {
        for _ in 0..100 {
            let mut actual_result = set2::CipherMode::Unknown;
            let detect_result = set2::detect_ecb_cbc(|input| {
                let (ciphertext, result) = set2::encryption_oracle(input);
                actual_result = result;
                return ciphertext;
            });
            println!(
                "actual_result: {:?}, detect_result: {:?}",
                actual_result, detect_result
            );
            assert_eq!(actual_result, detect_result);
        }
    }

    use set2::Oracle;

    #[test]
    fn byte_at_a_time_ecb_decryption_simple() {
        // Use a trait object here. Pretend we got the oracle from elsewhere
        // and don't know the underlying type, so we have to do all the work to
        // figure out the size, detect ECB mode, etc.
        let oracle = &set2::EcbOracleSimple::new() as &Oracle;
        let result = set2::byte_at_a_time_ecb_decryption_simple(oracle).unwrap();

        println!("result:\n{}", result);

        let result_ref = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                          aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                          dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                          YnkK";
        let result_ref = String::from_utf8(set1::base64_decode(result_ref).unwrap()).unwrap();
        assert_eq!(result, result_ref);
    }
}
