use crossbeam_channel::{Receiver, Sender, bounded};

#[derive(Debug)]
pub struct PacketBufPool {
    pool: Receiver<Vec<u8>>,
    returner: Sender<Vec<u8>>,
    buf_size: usize,
    max_return_capacity: usize,
}

#[derive(Clone, Debug)]
pub struct PacketBufReturner {
    returner: Sender<Vec<u8>>,
    max_return_capacity: usize,
}

impl PacketBufPool {
    pub fn new(pool_capacity: usize, buf_size: usize) -> Self {
        let capacity = pool_capacity.max(1);
        let max_return_capacity = buf_size.saturating_mul(8).max(buf_size);
        let (tx, rx) = bounded::<Vec<u8>>(capacity);
        for _ in 0..capacity {
            let _ = tx.try_send(Vec::with_capacity(buf_size));
        }
        PacketBufPool {
            pool: rx,
            returner: tx,
            buf_size,
            max_return_capacity,
        }
    }

    pub fn acquire(&self) -> Vec<u8> {
        match self.pool.try_recv() {
            Ok(mut buf) => {
                buf.clear();
                if buf.capacity() < self.buf_size {
                    buf.reserve(self.buf_size.saturating_sub(buf.capacity()));
                }
                buf
            }
            Err(_) => Vec::with_capacity(self.buf_size),
        }
    }

    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() > self.max_return_capacity {
            return;
        }
        buf.clear();
        let _ = self.returner.try_send(buf);
    }

    pub fn returner(&self) -> PacketBufReturner {
        PacketBufReturner {
            returner: self.returner.clone(),
            max_return_capacity: self.max_return_capacity,
        }
    }
}

impl PacketBufReturner {
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() > self.max_return_capacity {
            return;
        }
        buf.clear();
        let _ = self.returner.try_send(buf);
    }
}
