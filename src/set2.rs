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
        return Err("data length cannot be zero");
    }
    if data.len() % blocksize as usize != 0 {
        return Err("data length must be an integer multiple of block size");
    }

    let pad_byte: u8 = *data.last().unwrap();
    if pad_byte > blocksize {
        return Err("found pad byte larger than block size");
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
}
