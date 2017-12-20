
pub fn base64(hex: &[u8]) -> Result<String, &'static str> {
    let mut result = String::new();
    for group in hex.chunks(3) {
        let extended = match group.len() {
            1 => [group[0], 0,        0],
            2 => [group[0], group[1], 0],
            3 => [group[0], group[1], group[2]],
            _ => return Err("chunk too large!"),
        };

        for i in 0..4 {
            let sextet = match i {
                0 =>                               ((extended[0] & 0xFC) >> 2),
                1 => ((extended[0] & 0x03) << 4) | ((extended[1] & 0xF0) >> 4),
                2 => ((extended[1] & 0x0F) << 2) | ((extended[2] & 0xC0) >> 6),
                3 => ((extended[2] & 0x3F) << 0),
                _ => return Err("too many groups!"),
            };
            
            let symbol: char = match sextet {
                c @ 0  ... 25 => char::from(0x41 + c),
                c @ 26 ... 51 => char::from(0x61 + c - 26),
                c @ 52 ... 61 => char::from(0x30 + c - 52),
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

