use sodiumoxide::crypto::hash::sha256;
use cachet::v1::Cachet;
use keytree::v1::KeyTree;

use std::io::{self, Read};

// decrypts and merges an Iterator of (context,cachet)s into a single stream of decrypted bytes exports them via the Read trait.
pub struct Merge<'a, 'i> {
    key: &'a KeyTree,
    src: &'a mut Iterator<Item=&'i ([u8;32],Cachet)>,
    curr: Vec<u8>,
    cidx: usize,
}

impl <'a, 'i> Merge<'a, 'i> {
    pub fn new <I> (key: &'a KeyTree, iter: &'i mut I) -> Self where I:  Iterator<Item=&'i([u8;32],Cachet)> {
        Self{key: key, src:iter, curr:Vec::with_capacity(0), cidx: 0}
    }

    pub fn decrypt (key: &KeyTree, context: &[u8;32], cachet: &Cachet) -> Result<Vec<u8>, LockBlockError> {
        key.derive_and_decrypt(context, cachet).map_err(|_| LockBlockError::DecryptionError)
    }
}

impl <'a, 'i> Read for Merge<'a, 'i> {
    fn read(&mut self, buff: &mut [u8]) -> io::Result<usize> {
        let mut bidx = 0;
        loop {
            // BASECASE: written max bytes buffer will hold
            if bidx == buff.len() {
                return Ok(bidx);
            }
            // BASECASE: emptied our current vec, grab the next one from src
            if self.cidx == self.curr.len() {
                let next_opt = self.src.next();
                // src has run out of items,
                if next_opt.is_none() {
                    return Ok(bidx);
                }
                let (ctx, cachet) = next_opt.unwrap();
                self.curr = Self::decrypt(self.key, &ctx, cachet).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Could Not Decrypt"))?;
                self.cidx = 0;
                continue;
            }
            // LOOP: copy byte from self.cur into buffer
            buff[bidx] = self.curr[self.cidx];
            self.cidx += 1;
            bidx += 1;
        }
    }
}

// Reads unencryted bytes into an Iterator that yeilds encrypted (context,cachet) encrypted blocks
// of a fixed size.
struct Split<'a, R> {
    key: &'a KeyTree,
    read: R,
    size: usize,
}

impl<'a, R> Split<'a, R> {
    pub fn new(key: &'a KeyTree, read: R, size: usize) -> Self {
        Self{key, read,size}
    }

    pub fn encrypt (key: &KeyTree, data:&[u8]) -> Result<([u8;32], Cachet), LockBlockError> {
        let sha256::Digest(hash) = sha256::hash(data);
        let cachet = key.derive_and_encrypt(&hash,data).map_err(|_| LockBlockError::EncryptionError)?;
        Ok( (hash, cachet) )
    }

}

impl<'a, R> Iterator for Split<'a, R> where R: Read {
    type Item = Result<([u8;32], Cachet), LockBlockError>;

    // can call Some(Err(....)) forever, use a iter::Collect with a Result type
    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = Vec::with_capacity(self.size);
        self.read
            .by_ref()
            .take(buffer.capacity() as u64)
            .read_to_end(&mut buffer)
            .map_err( |e| LockBlockError::IOError(e) )
            .and_then( |c| if c == 0 { Ok(None) } else {
                Self::encrypt(self.key, &buffer[..c]).map(|t| Some(t))
            })
            .transpose()
    }
}

#[derive(Debug)]
pub enum LockBlockError {
    IOError(io::Error),
    EncryptionSourceError,
    EncryptionError,
    DecryptionError,
}

#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::{self as aead, Nonce, Key as AeadKey};
    use keytree::v1::{KeyTree, KeyTreeError};
    use std::io::{self, Read};

    fn gen_root () -> KeyTree {
        let k = aead::gen_key();
        let root_res = KeyTree::from_root(k);
        assert!(root_res.is_ok());
        root_res.unwrap()
    }

    #[test]
    fn merge_test ()  {
        let root = gen_root();
        let test = b"hello cruel world";
        let iter = super::Split::new(&root, test.as_ref(), 0x03);
        let mut src = Vec::new();
        for res in iter {
            assert!(res.is_ok());
            src.push(res.unwrap());
        }
        assert_eq!(6, src.len());
        let mut iter = src.iter();
        let mut mrg = super::Merge::new(&root,&mut iter);
        let mut dst:Vec<u8> = Vec::with_capacity(test.len());
        let mut buf = [0u8;2];
        let mut bytes_read = 0;
        loop {
            let res = mrg.read(&mut buf);
            assert!(res.is_ok());
            bytes_read = res.unwrap();
            for i in 0..bytes_read {
                dst.push(buf[i]);
            }
            if bytes_read == 0 { break; }
        }
        assert_eq!(dst, test);
    }


    #[test]
    fn split_test () {
        let root = gen_root();
        let iter = super::Split::new(&root, b"hello".as_ref(), 0x02);
        let mut count = 0;
        for res in iter {
            assert!(res.is_ok());
            let (hash, cachet) = res.unwrap();
            let decrypted = super::Merge::decrypt(&root,&hash,&cachet);
            assert!(decrypted.is_ok());
            assert_eq!(decrypted.unwrap(), match count {
                0 => b"he".to_vec(),
                1 => b"ll".to_vec(),
                2 => b"o".to_vec(),
                _ => Vec::new()
            });
            count = count + 1;
        }
    }
}
