use smallvec::SmallVec;

pub type SmallBuf = SmallVec<[u8; 128]>;
pub type MediumBuf = SmallVec<[u8; 512]>;
pub type SmallStringBuf = SmallVec<[u8; 64]>;

pub struct BufferPool {
    pool: Vec<Vec<u8>>,
    size: usize,
}

impl BufferPool {
    pub fn new(capacity: usize, buf_size: usize) -> Self {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            pool.push(vec![0u8; buf_size]);
        }
        BufferPool { pool, size: buf_size }
    }

    pub fn acquire(&mut self) -> Vec<u8> {
        self.pool.pop().unwrap_or_else(|| vec![0u8; self.size])
    }

    pub fn release(&mut self, mut buf: Vec<u8>) {
        buf.truncate(self.size);
        buf.fill(0);
        if self.pool.len() < self.pool.capacity() {
            self.pool.push(buf);
        }
    }

    pub fn len(&self) -> usize { self.pool.len() }
}

pub fn read_line_small(src: &[u8], start: usize) -> Option<(SmallStringBuf, usize)> {
    let mut line = SmallStringBuf::new();
    let mut pos = start;
    while pos < src.len() {
        match src[pos] {
            b'\n' => return Some((line, pos + 1)),
            b'\r' => {
                if pos + 1 < src.len() && src[pos + 1] == b'\n' {
                    return Some((line, pos + 2));
                }
                return Some((line, pos + 1));
            }
            c => line.push(c),
        }
        pos += 1;
    }
    if line.is_empty() { None } else { Some((line, pos)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_buf_allocation() {
        let buf: SmallBuf = SmallVec::new();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_buffer_pool_acquire_release() {
        let mut pool = BufferPool::new(4, 1024);
        assert_eq!(pool.len(), 4);
        let buf = pool.acquire();
        assert_eq!(buf.len(), 1024);
        assert_eq!(pool.len(), 3);
        pool.release(buf);
        assert_eq!(pool.len(), 4);
    }

    #[test]
    fn test_read_line_small() {
        let data = b"hello\nworld\r\nend";
        let (line, pos) = read_line_small(data, 0).unwrap();
        assert_eq!(&line[..], b"hello");
        assert_eq!(pos, 6);

        let (line, pos) = read_line_small(data, pos).unwrap();
        assert_eq!(&line[..], b"world");
        assert_eq!(pos, 13);
    }

    #[test]
    fn test_read_line_small_empty() {
        assert!(read_line_small(b"", 0).is_none());
    }
}
