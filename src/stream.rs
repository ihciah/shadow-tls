//! Stream wrapper to calculate hmac.

use std::{cell::RefCell, rc::Rc};

use hmac::Mac;
use monoio::{
    buf::{IoVecWrapper, IoVecWrapperMut},
    io::{
        as_fd::{AsReadFd, AsWriteFd},
        AsyncReadRent, AsyncWriteRent,
    },
};

pub trait HashedStream {
    fn hash_stream(&self) -> [u8; 20];
}

pub struct HashedReadStream<S> {
    raw: S,
    hmac: hmac::Hmac<sha1::Sha1>,
}

// # Safety
// Here we does not make read and write related, so if S is Split, Self is Split.
unsafe impl<S: monoio::io::Split> monoio::io::Split for HashedReadStream<S> {}

impl<S> HashedReadStream<S> {
    pub fn new(raw: S, password: &[u8]) -> Result<Self, hmac::digest::InvalidLength> {
        Ok(Self {
            raw,
            hmac: hmac::Hmac::new_from_slice(password)?,
        })
    }

    pub fn into_inner(self) -> S {
        self.raw
    }

    pub fn hash(&self) -> [u8; 20] {
        self.hmac
            .clone()
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("unexpected digest length")
    }
}

impl<S> HashedStream for HashedReadStream<S> {
    fn hash_stream(&self) -> [u8; 20] {
        self.hash()
    }
}

pub struct HashedWriteStream<S> {
    raw: S,
    hmac: Rc<RefCell<(bool, hmac::Hmac<sha1::Sha1>)>>,
}

// # Safety
// Here we does not make read and write related, so if S is Split, Self is Split.
unsafe impl<S: monoio::io::Split> monoio::io::Split for HashedWriteStream<S> {}
unsafe impl<S: monoio::io::Split> monoio::io::Split for &mut HashedWriteStream<S> {}

impl<S: AsReadFd> AsReadFd for HashedWriteStream<S> {
    fn as_reader_fd(&mut self) -> &monoio::io::as_fd::SharedFdWrapper {
        self.raw.as_reader_fd()
    }
}

impl<S: AsWriteFd> AsWriteFd for HashedWriteStream<S> {
    fn as_writer_fd(&mut self) -> &monoio::io::as_fd::SharedFdWrapper {
        self.raw.as_writer_fd()
    }
}

impl<S> HashedWriteStream<S> {
    pub fn new(raw: S, password: &[u8]) -> Result<Self, hmac::digest::InvalidLength> {
        Ok(Self {
            raw,
            hmac: Rc::new(RefCell::new((true, hmac::Hmac::new_from_slice(password)?))),
        })
    }

    pub fn into_inner(self) -> S {
        self.raw
    }

    pub fn hash(&self) -> [u8; 20] {
        self.hmac
            .borrow()
            .clone()
            .1
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("unexpected digest length")
    }

    pub fn hmac_handler(&self) -> HmacHandler {
        HmacHandler(self.hmac.clone())
    }
}

pub struct HmacHandler(Rc<RefCell<(bool, hmac::Hmac<sha1::Sha1>)>>);

impl HmacHandler {
    pub fn hash(&self) -> [u8; 20] {
        self.0
            .borrow()
            .clone()
            .1
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("unexpected digest length")
    }

    pub fn disable(&mut self) {
        self.0.borrow_mut().0 = false;
    }
}

impl<S> HashedStream for HashedWriteStream<S> {
    fn hash_stream(&self) -> [u8; 20] {
        self.hash()
    }
}

impl<S: AsyncReadRent> AsyncReadRent for HashedReadStream<S> {
    type ReadFuture<'a, B> = impl std::future::Future<Output = monoio::BufResult<usize, B>> +'a where
        B: monoio::buf::IoBufMut + 'a, S: 'a;
    type ReadvFuture<'a, B> = impl std::future::Future<Output = monoio::BufResult<usize, B>> +'a where
        B: monoio::buf::IoVecBufMut + 'a, S: 'a;

    fn read<T: monoio::buf::IoBufMut>(&mut self, mut buf: T) -> Self::ReadFuture<'_, T> {
        async move {
            let ptr = buf.write_ptr();
            let (result, buf) = self.raw.read(buf).await;
            if let Ok(n) = result {
                // Safety: we can make sure the ptr and n are valid.
                self.hmac
                    .update(unsafe { std::slice::from_raw_parts(ptr, n) });
            }
            (result, buf)
        }
    }

    fn readv<T: monoio::buf::IoVecBufMut>(&mut self, mut buf: T) -> Self::ReadvFuture<'_, T> {
        async move {
            let slice = match IoVecWrapperMut::new(buf) {
                Ok(slice) => slice,
                Err(buf) => return (Ok(0), buf),
            };

            let (result, slice) = self.read(slice).await;
            buf = slice.into_inner();
            if let Ok(n) = result {
                unsafe { buf.set_init(n) };
            }
            (result, buf)
        }
    }
}

impl<S: AsyncWriteRent> AsyncWriteRent for HashedReadStream<S> {
    type WriteFuture<'a, T> = S::WriteFuture<'a, T> where
    T: monoio::buf::IoBuf + 'a, Self: 'a;

    type WritevFuture<'a, T>= S::WritevFuture<'a, T> where
    T: monoio::buf::IoVecBuf + 'a, Self: 'a;

    type FlushFuture<'a> = S::FlushFuture<'a> where Self: 'a;

    type ShutdownFuture<'a> = S::ShutdownFuture<'a> where Self: 'a;

    fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> Self::WriteFuture<'_, T> {
        self.raw.write(buf)
    }

    fn writev<T: monoio::buf::IoVecBuf>(&mut self, buf_vec: T) -> Self::WritevFuture<'_, T> {
        self.raw.writev(buf_vec)
    }

    fn flush(&mut self) -> Self::FlushFuture<'_> {
        self.raw.flush()
    }

    fn shutdown(&mut self) -> Self::ShutdownFuture<'_> {
        self.raw.shutdown()
    }
}

impl<S: AsyncReadRent> AsyncReadRent for HashedWriteStream<S> {
    type ReadFuture<'a, T> = <S as AsyncReadRent>::ReadFuture<'a, T> where
        T: monoio::buf::IoBufMut + 'a, Self: 'a;
    type ReadvFuture<'a, T> = <S as AsyncReadRent>::ReadvFuture<'a, T> where
        T: monoio::buf::IoVecBufMut + 'a, Self: 'a;

    fn read<T: monoio::buf::IoBufMut>(&mut self, buf: T) -> Self::ReadFuture<'_, T> {
        self.raw.read(buf)
    }

    fn readv<T: monoio::buf::IoVecBufMut>(&mut self, buf: T) -> Self::ReadvFuture<'_, T> {
        self.raw.readv(buf)
    }
}

impl<S: AsyncWriteRent> AsyncWriteRent for HashedWriteStream<S> {
    type WriteFuture<'a, T> = impl std::future::Future<Output = monoio::BufResult<usize, T>> +'a where
        T: monoio::buf::IoBuf + 'a, S: 'a;

    type WritevFuture<'a, T> = impl std::future::Future<Output = monoio::BufResult<usize, T>> +'a where
        T: monoio::buf::IoVecBuf + 'a, S: 'a;

    type FlushFuture<'a> = S::FlushFuture<'a> where Self: 'a;

    type ShutdownFuture<'a> = S::ShutdownFuture<'a> where Self: 'a;

    fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> Self::WriteFuture<'_, T> {
        async move {
            let ptr = buf.read_ptr();
            let (result, buf) = self.raw.write(buf).await;
            if let Ok(n) = result {
                let mut eh = self.hmac.borrow_mut();
                if eh.0 {
                    // Safety: we can make sure the ptr and n are valid.
                    eh.1.update(unsafe { std::slice::from_raw_parts(ptr, n) });
                }
            }
            (result, buf)
        }
    }

    fn writev<T: monoio::buf::IoVecBuf>(&mut self, buf: T) -> Self::WritevFuture<'_, T> {
        async move {
            let slice = match IoVecWrapper::new(buf) {
                Ok(slice) => slice,
                Err(buf) => return (Ok(0), buf),
            };

            let (result, slice) = self.write(slice).await;
            (result, slice.into_inner())
        }
    }

    fn flush(&mut self) -> Self::FlushFuture<'_> {
        self.raw.flush()
    }

    fn shutdown(&mut self) -> Self::ShutdownFuture<'_> {
        self.raw.shutdown()
    }
}
