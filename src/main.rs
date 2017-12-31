#![feature(inclusive_range_syntax)]

#[macro_use]
extern crate maplit;

mod set1;
use set1::*;
/*
extern crate hex;
use hex::FromHex;
*/

use std::str;


use std::fs::File;
//use std::io::BufReader;
use std::io::prelude::*;

/*
use std::collections::BTreeMap;
*/
/*
extern crate openssl;
use openssl::symm::{decrypt, Cipher};
*/

fn main() {
    let mut f = File::open("challenge-data/6.txt").unwrap();
    let mut encoded = String::new();
    f.read_to_string(&mut encoded).unwrap();
    let decoded = base64_decode(&encoded).unwrap();

    let mut results: Vec<(f32, usize)> = Vec::with_capacity(40);

    for keysize in 2..=40 {
        let sequences = decoded.chunks(keysize).collect::<Vec<&[u8]>>();
        let norm_distances = sequences.chunks(2)
            .filter(|maybe_pair| maybe_pair.len() == 2)
            .filter(|maybe_same_len| maybe_same_len[0].len() == maybe_same_len[1].len())
            .map(|pair| hamming_distance(pair[0], pair[1]).unwrap() as f32 / keysize as f32)
            .collect::<Vec<f32>>();

        let norm_dist_avg: f32 = &norm_distances.iter().sum() / norm_distances.len() as f32;

        results.push((norm_dist_avg, keysize));
    }

    results.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    for &(dist, keysize) in &results {
        println!("dist: {}\t\tkeysize: {}", dist, keysize);
    }

    let keysize = results[0].1;
    println!("keysize: {}", keysize);

    let sequences = decoded.chunks(keysize).collect::<Vec<&[u8]>>();
    println!("sequences.len: {}", sequences.len());

    let mut transposed: Vec<Vec<u8>> = Vec::with_capacity(keysize);
    for i in 0..keysize {
        let mut line = Vec::with_capacity(sequences.len());
        for j in 0..sequences.len() {
            if i < sequences[j].len() {
                line.push(sequences[j][i]);
            }
        }
        transposed.push(line);
    }

    let mut key: Vec<u8> = Vec::with_capacity(keysize);

    for block in transposed {
        let key_byte = find_best_single_byte_xor(&block);
        key.push(key_byte);
        println!("key byte: {:02x} ('{}')", key_byte, key_byte as char);
    }

    let plaintext = xor_repeat(&decoded, &key);

    println!("plaintext:\n{}", str::from_utf8(&plaintext).unwrap());

}
