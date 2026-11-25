//! TCP framing (spec §3.1): a 4-byte little-endian length, then the node
//! header and payload.

use std::fmt;

use super::header::HEADER_LEN;

/// Largest `frame_len` this node sends. 2.6.4 peers close the connection
/// above it, so it holds for every frame, tails included.
pub const MAX_SEND_FRAME: usize = 2000;
/// Largest `frame_len` this node accepts (the 2.7.x limit).
pub const MAX_RECV_FRAME: usize = 4096;
const LEN_PREFIX: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// `frame_len` below a node header: close the connection.
    TooShort(u32),
    /// `frame_len` above [`MAX_RECV_FRAME`]: close the connection.
    TooLong(u32),
    /// A packet this node was about to send is above [`MAX_SEND_FRAME`].
    SendTooLong(usize),
    /// More than one largest frame left over after the caller read out
    /// every whole frame: the caller did not drain, or the stream is junk.
    Overflow,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooShort(n) => {
                write!(f, "mesh TCP frame of {n} bytes is shorter than a header")
            }
            FrameError::TooLong(n) => write!(f, "mesh TCP frame of {n} bytes is too long"),
            FrameError::SendTooLong(n) => write!(f, "mesh packet of {n} bytes is too long to send"),
            FrameError::Overflow => f.write_str("mesh TCP receive buffer is full"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Frames one packet (header and payload, already sealed).
pub fn encode_frame(packet: &[u8]) -> Result<Vec<u8>, FrameError> {
    if packet.len() < HEADER_LEN {
        return Err(FrameError::TooShort(packet.len() as u32));
    }
    if packet.len() > MAX_SEND_FRAME {
        return Err(FrameError::SendTooLong(packet.len()));
    }
    let mut frame = Vec::with_capacity(LEN_PREFIX + packet.len());
    frame.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}

/// Splits a TCP byte stream into packets. Reads may end anywhere.
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    /// Bytes at the front of `buf` already returned as packets.
    start: usize,
}

/// Most bytes left over between reads once whole frames are read out: one
/// largest frame. A [`FrameDecoder`] therefore holds at most this plus one
/// read, whatever size the caller reads in.
pub const MAX_LEFTOVER: usize = LEN_PREFIX + MAX_RECV_FRAME;

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes read from the connection, of any length. The caller
    /// reads every whole packet out between reads; what is left then is at
    /// most [`MAX_LEFTOVER`], and more is refused.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        if self.buf.len() > MAX_LEFTOVER {
            return Err(FrameError::Overflow);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Bytes held that do not yet form a whole frame.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// The next whole packet. An error is final: the connection must close.
    pub fn next_packet(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let pending = &self.buf[self.start..];
        let Some(prefix) = pending.get(..LEN_PREFIX) else {
            return Ok(None);
        };
        let len = u32::from_le_bytes(prefix.try_into().unwrap());
        if (len as usize) < HEADER_LEN {
            return Err(FrameError::TooShort(len));
        }
        if len as usize > MAX_RECV_FRAME {
            return Err(FrameError::TooLong(len));
        }
        let end = LEN_PREFIX + len as usize;
        if pending.len() < end {
            return Ok(None);
        }
        let packet = pending[LEN_PREFIX..end].to_vec();
        self.start += end;
        Ok(Some(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    #[test]
    fn frames_round_trip_across_arbitrary_reads() {
        let packets = [packet(16), packet(100), packet(MAX_SEND_FRAME)];
        let stream: Vec<u8> = packets
            .iter()
            .flat_map(|p| encode_frame(p).unwrap())
            .collect();
        for chunk in [1, 3, 7, 4096] {
            let mut decoder = FrameDecoder::new();
            let mut out = Vec::new();
            for piece in stream.chunks(chunk) {
                decoder.push(piece).unwrap();
                while let Some(packet) = decoder.next_packet().unwrap() {
                    out.push(packet);
                }
            }
            assert_eq!(out, packets, "chunk {chunk}");
            assert_eq!(decoder.buffered(), 0);
        }
    }

    #[test]
    fn send_limit_is_two_thousand() {
        assert_eq!(
            encode_frame(&packet(MAX_SEND_FRAME + 1)),
            Err(FrameError::SendTooLong(MAX_SEND_FRAME + 1))
        );
        assert_eq!(encode_frame(&packet(15)), Err(FrameError::TooShort(15)));
        assert_eq!(&encode_frame(&packet(16)).unwrap()[..4], &[16, 0, 0, 0]);
    }

    #[test]
    fn receive_accepts_up_to_4096_and_rejects_bad_lengths() {
        let mut decoder = FrameDecoder::new();
        decoder
            .push(&(MAX_RECV_FRAME as u32).to_le_bytes())
            .unwrap();
        decoder.push(&packet(MAX_RECV_FRAME)).unwrap();
        assert_eq!(
            decoder.next_packet().unwrap().unwrap().len(),
            MAX_RECV_FRAME
        );

        let mut decoder = FrameDecoder::new();
        decoder.push(&4097u32.to_le_bytes()).unwrap();
        assert_eq!(decoder.next_packet(), Err(FrameError::TooLong(4097)));

        let mut decoder = FrameDecoder::new();
        decoder.push(&15u32.to_le_bytes()).unwrap();
        assert_eq!(decoder.next_packet(), Err(FrameError::TooShort(15)));

        let mut decoder = FrameDecoder::new();
        decoder.push(&[16, 0, 0]).unwrap();
        assert_eq!(decoder.next_packet(), Ok(None));
    }

    #[test]
    fn buffer_is_bounded_and_compacted() {
        // One read of any size is taken; left undrained, the next is not.
        let mut decoder = FrameDecoder::new();
        decoder.push(&vec![0xff; 256 * 1024]).unwrap();
        assert_eq!(decoder.push(&[0]), Err(FrameError::Overflow));
        // A large read of many whole frames is fine once drained.
        let frame = encode_frame(&packet(MAX_SEND_FRAME)).unwrap();
        let stream: Vec<u8> = (0..100).flat_map(|_| frame.clone()).collect();
        let mut decoder = FrameDecoder::new();
        decoder.push(&stream).unwrap();
        let mut count = 0;
        while decoder.next_packet().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 100);
        decoder.push(&frame[..10]).unwrap();
        assert_eq!(decoder.buffered(), 10);
        // Whole frames read out make room again.
        let frame = encode_frame(&packet(MAX_SEND_FRAME)).unwrap();
        let mut decoder = FrameDecoder::new();
        for _ in 0..1000 {
            decoder.push(&frame).unwrap();
            assert!(decoder.next_packet().unwrap().is_some());
            assert_eq!(decoder.buffered(), 0);
        }
    }
}
