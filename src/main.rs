mod set1;
use set1::base64;

extern crate hex;
use hex::FromHex;


fn main() {
    let example_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let example_bytes = Vec::from_hex(example_hex).unwrap();
    println!("example_hex: {}", example_hex);
    print!("example_bytes: ");
    for byte in &example_bytes {
        print!("{:x} ", byte);
    }
    println!();
    println!("bytes: {}", example_bytes.len());

    if let Ok(b64) = base64(&example_bytes) {
        println!("{}", b64);
    }

    let test = "foobar".as_bytes();
    println!("{:?}", test);
    if let Ok(b64) = base64(&test) {
        println!("{}", b64);
    }
}
