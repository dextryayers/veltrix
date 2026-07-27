use nom::{
    IResult,
    bytes::complete::{tag, take, take_until, take_while},
    number::complete::{be_u16, be_u32, be_u8, le_u16, le_u32},
    combinator::{map, map_res},
    branch::alt,
};

pub fn parse_be_u8(input: &[u8]) -> IResult<&[u8], u8> {
    be_u8(input)
}

pub fn parse_be_u16(input: &[u8]) -> IResult<&[u8], u16> {
    be_u16(input)
}

pub fn parse_be_u32(input: &[u8]) -> IResult<&[u8], u32> {
    be_u32(input)
}

pub fn parse_le_u16(input: &[u8]) -> IResult<&[u8], u16> {
    le_u16(input)
}

pub fn parse_le_u32(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
}

pub fn parse_null_terminated(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_until("\0")(input)
}

pub fn parse_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((
        map(take_until("\r\n"), |line: &[u8]| {
            let remaining = &input[line.len() + 2..];
            unsafe { std::slice::from_raw_parts(line.as_ptr(), line.len()) }
        }),
        map(take_until("\n"), |line: &[u8]| {
            unsafe { std::slice::from_raw_parts(line.as_ptr(), line.len()) }
        }),
    ))(input)
}

pub fn skip_crlf(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((tag("\r\n"), tag("\n")))(input)
}

pub fn parse_until_crlf(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_until("\n")(input)
}

pub fn parse_fixed_string<'a>(n: usize) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    move |input| take(n)(input)
}

pub fn parse_cstring(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, data) = take_until("\0")(input)?;
    let (input, _) = tag("\0")(input)?;
    Ok((input, data))
}

pub fn parse_pascal_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, len) = be_u8(input)?;
    take(len as usize)(input)
}

pub fn parse_pascal_u16_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, len) = be_u16(input)?;
    take(len as usize)(input)
}

pub fn parse_whitespace(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|b: u8| b == b' ' || b == b'\t')(input)
}

pub fn parse_digit(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|b: u8| b.is_ascii_digit())(input)
}

pub fn parse_alphanumeric(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|b: u8| b.is_ascii_alphanumeric())(input)
}

pub fn parse_int(input: &[u8]) -> IResult<&[u8], u64> {
    map_res(
        take_while(|b: u8| b.is_ascii_digit()),
        |s: &[u8]| {
            let s = std::str::from_utf8(s).map_err(|_| nom::Err::Error(nom::error::Error::new(s, nom::error::ErrorKind::Digit)))?;
            s.parse::<u64>().map_err(|_| nom::Err::Error(nom::error::Error::new(s.as_bytes(), nom::error::ErrorKind::Digit)))
        }
    )(input)
}

pub fn parse_tag<'a>(expected: &'static [u8]) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    tag(expected)
}

pub fn parse_version_string(input: &[u8]) -> IResult<&[u8], (u8, u8, u8)> {
    let (input, major) = parse_digit(input)?;
    let (input, _) = tag(".")(input)?;
    let (input, minor) = parse_digit(input)?;
    let (input, _) = tag(".")(input)?;
    let (input, patch) = parse_digit(input)?;
    let major = std::str::from_utf8(major).unwrap_or("0").parse::<u8>().unwrap_or(0);
    let minor = std::str::from_utf8(minor).unwrap_or("0").parse::<u8>().unwrap_or(0);
    let patch = std::str::from_utf8(patch).unwrap_or("0").parse::<u8>().unwrap_or(0);
    Ok((input, (major, minor, patch)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_be_u16() {
        let data = [0x00, 0x01];
        let (remaining, val) = parse_be_u16(&data).unwrap();
        assert_eq!(val, 1);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_parse_be_u32() {
        let data = [0x00, 0x00, 0x00, 0x2a];
        let (_, val) = parse_be_u32(&data).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_parse_null_terminated() {
        let data = b"hello\0world";
        let (remaining, val) = parse_null_terminated(data).unwrap();
        assert_eq!(val, b"hello");
        assert_eq!(remaining, b"\0world");
    }

    #[test]
    fn test_parse_cstring() {
        let data = b"test\0rest";
        let (remaining, val) = parse_cstring(data).unwrap();
        assert_eq!(val, b"test");
        assert_eq!(remaining, b"rest");
    }

    #[test]
    fn test_parse_pascal_string() {
        let data = [0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f];
        let (_, val) = parse_pascal_string(&data).unwrap();
        assert_eq!(val, b"hello");
    }

    #[test]
    fn test_parse_digit() {
        let data = b"123abc";
        let (remaining, val) = parse_digit(data).unwrap();
        assert_eq!(val, b"123");
        assert_eq!(remaining, b"abc");
    }

    #[test]
    fn test_parse_int() {
        let data = b"456";
        let (_, val) = parse_int(data).unwrap();
        assert_eq!(val, 456);
    }

    #[test]
    fn test_parse_version_string() {
        let data = b"1.2.3extra";
        let (remaining, (major, minor, patch)) = parse_version_string(data).unwrap();
        assert_eq!((major, minor, patch), (1, 2, 3));
        assert_eq!(remaining, b"extra");
    }

    #[test]
    fn test_parse_le_u16() {
        let data = [0x01, 0x00];
        let (_, val) = parse_le_u16(&data).unwrap();
        assert_eq!(val, 1);
    }

    #[test]
    fn test_parse_fixed_string() {
        let data = b"abcdefgh";
        let mut parser = parse_fixed_string(4);
        let (remaining, val) = parser(data).unwrap();
        assert_eq!(val, b"abcd");
        assert_eq!(remaining, b"efgh");
    }
}
