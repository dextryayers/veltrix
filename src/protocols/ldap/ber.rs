pub fn ber_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

pub fn ber_integer(value: i32) -> Vec<u8> {
    let bytes = if value < 0x80 {
        vec![value as u8]
    } else if value < 0x8000 {
        vec![(value >> 8) as u8, value as u8]
    } else {
        vec![(value >> 24) as u8, (value >> 16) as u8, (value >> 8) as u8, value as u8]
    };
    let mut result = vec![0x02u8];
    result.extend_from_slice(&ber_len(bytes.len()));
    result.extend_from_slice(&bytes);
    result
}

pub fn ber_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04u8];
    result.extend_from_slice(&ber_len(data.len()));
    result.extend_from_slice(data);
    result
}

pub fn ber_context_tag(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x80 | tag];
    result.extend_from_slice(&ber_len(data.len()));
    result.extend_from_slice(data);
    result
}

pub fn ber_sequence(items: &[u8]) -> Vec<u8> {
    let mut result = vec![0x30u8];
    result.extend_from_slice(&ber_len(items.len()));
    result.extend_from_slice(items);
    result
}

pub fn ber_application(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x60 | tag];
    result.extend_from_slice(&ber_len(data.len()));
    result.extend_from_slice(data);
    result
}
