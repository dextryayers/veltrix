use bytes::{Bytes, BytesMut, BufMut};
use std::io;

pub struct ReadBuffer {
    inner: BytesMut,
}

impl ReadBuffer {
    pub fn with_capacity(cap: usize) -> Self {
        ReadBuffer { inner: BytesMut::with_capacity(cap) }
    }

    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    pub fn put_slice(&mut self, data: &[u8]) {
        self.inner.put_slice(data);
    }

    pub fn try_get_line(&mut self) -> Option<Bytes> {
        let pos = self.inner.iter().position(|&b| b == b'\n')?;
        let len = if pos > 0 && self.inner[pos - 1] == b'\r' { pos - 1 } else { pos };
        let mut line = self.inner.split_to(pos + 1);
        line.truncate(len);
        Some(line.freeze())
    }

    pub fn try_get_until(&mut self, delim: &[u8]) -> Option<Bytes> {
        let pos = self.inner.windows(delim.len()).position(|w| w == delim)?;
        let end = pos + delim.len();
        let chunk = self.inner.split_to(end);
        Some(chunk.freeze())
    }

    pub fn remaining(&self) -> &[u8] { &self.inner }
    pub fn remaining_mut(&mut self) -> &mut BytesMut { &mut self.inner }
    pub fn len(&self) -> usize { self.inner.len() }
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
    pub fn clear(&mut self) { self.inner.clear(); }

    pub fn split(&mut self, at: usize) -> Bytes {
        self.inner.split_to(at).freeze()
    }

    pub fn freeze(&self) -> Bytes {
        self.inner.clone().freeze()
    }
}

pub struct WriteBuffer {
    inner: BytesMut,
}

impl WriteBuffer {
    pub fn new() -> Self {
        WriteBuffer { inner: BytesMut::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        WriteBuffer { inner: BytesMut::with_capacity(cap) }
    }

    pub fn put_u8(&mut self, v: u8) { self.inner.put_u8(v); }
    pub fn put_u16_be(&mut self, v: u16) { self.inner.put_u16(v); }
    pub fn put_u32_be(&mut self, v: u32) { self.inner.put_u32(v); }
    pub fn put_slice(&mut self, data: &[u8]) { self.inner.put_slice(data); }
    pub fn put(&mut self, bytes: &[u8]) { self.inner.put_slice(bytes); }

    pub fn as_slice(&self) -> &[u8] { &self.inner }
    pub fn len(&self) -> usize { self.inner.len() }
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }

    pub fn to_bytes(self) -> Bytes { self.inner.freeze() }
}

impl AsRef<[u8]> for WriteBuffer {
    fn as_ref(&self) -> &[u8] { &self.inner }
}

pub fn read_exact_buf(stream: &mut (impl io::Read + Unpin), buf: &mut BytesMut, n: usize) -> io::Result<()> {
    buf.reserve(n);
    while buf.len() < n {
        let read = stream.read(buf)?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_buffer() {
        let mut wb = WriteBuffer::with_capacity(16);
        wb.put_u8(0x01);
        wb.put_u16_be(0x0203);
        wb.put_slice(b"hello");
        assert_eq!(wb.as_slice(), &[0x01, 0x02, 0x03, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    }

    #[test]
    fn test_read_buffer_line() {
        let mut rb = ReadBuffer::with_capacity(64);
        rb.put_slice(b"line1\r\nline2\nline3\r\n");
        let line1 = rb.try_get_line().unwrap();
        assert_eq!(&line1[..], b"line1");
        let line2 = rb.try_get_line().unwrap();
        assert_eq!(&line2[..], b"line2");
        let line3 = rb.try_get_line().unwrap();
        assert_eq!(&line3[..], b"line3");
        assert!(rb.try_get_line().is_none());
    }

    #[test]
    fn test_read_buffer_until() {
        let mut rb = ReadBuffer::with_capacity(32);
        rb.put_slice(b"hello\x00\x00world");
        let chunk = rb.try_get_until(b"\x00\x00").unwrap();
        assert_eq!(&chunk[..], b"hello\x00\x00");
        assert_eq!(rb.remaining(), b"world");
    }
}
