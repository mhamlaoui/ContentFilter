//! A minimal, self-contained toy DNS-over-UDP server used to assert
//! sinkhole/resolve behavior in tests, standing in for `svc-resolver` until
//! that component exists. Handles exactly one question per query, no name
//! compression on the wire in (queries are built by [`query`] below, which
//! never compresses), and only A/IN records.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    /// Respond NXDOMAIN, the same signal `svc-resolver` gives for a blocked name.
    Sinkhole,
    /// Respond with an A record.
    Resolve(Ipv4Addr),
}

pub struct DnsFixture {
    addr: SocketAddr,
    _handle: thread::JoinHandle<()>,
}

impl DnsFixture {
    /// Starts the fixture on an ephemeral loopback port. Names not present
    /// in `records` are treated as NXDOMAIN, matching a default-deny resolver.
    pub fn start(records: HashMap<String, Outcome>) -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let addr = socket.local_addr()?;
        let records = Arc::new(records);
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                let (len, src) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if let Some(resp) = handle_query(&buf[..len], &records) {
                    let _ = socket.send_to(&resp, src);
                }
            }
        });
        Ok(Self {
            addr,
            _handle: handle,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

fn parse_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compressed names are never sent by our own client
        }
        pos += 1;
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }
    Some((labels.join(".") + ".", pos))
}

fn encode_name(domain: &str, out: &mut Vec<u8>) {
    for label in domain.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn handle_query(msg: &[u8], records: &HashMap<String, Outcome>) -> Option<Vec<u8>> {
    if msg.len() < 12 {
        return None;
    }
    let id = [msg[0], msg[1]];
    let req_flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount != 1 {
        return None;
    }
    let (qname, qname_end) = parse_name(msg, 12)?;
    if msg.len() < qname_end + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[qname_end], msg[qname_end + 1]]);
    let qclass = u16::from_be_bytes([msg[qname_end + 2], msg[qname_end + 3]]);

    let domain = qname.trim_end_matches('.').to_ascii_lowercase();
    let outcome = if qtype == 1 && qclass == 1 {
        records.get(&domain).copied()
    } else {
        None
    };

    let rd = req_flags & 0x0100;
    let mut resp = Vec::with_capacity(64);
    resp.extend_from_slice(&id);
    let (rcode, ancount): (u16, u16) = match outcome {
        Some(Outcome::Resolve(_)) => (0, 1),
        Some(Outcome::Sinkhole) | None => (3, 0), // NXDOMAIN
    };
    let flags: u16 = 0x8000 // QR = response
        | 0x0400 // AA
        | rd
        | 0x0080 // RA
        | rcode;
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    resp.extend_from_slice(&ancount.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes()); // nscount
    resp.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_name(&domain, &mut resp);
    resp.extend_from_slice(&qtype.to_be_bytes());
    resp.extend_from_slice(&qclass.to_be_bytes());
    if let Some(Outcome::Resolve(ip)) = outcome {
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&ip.octets());
    }
    Some(resp)
}

fn build_query(id: u16, domain: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    msg.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    encode_name(domain, &mut msg);
    msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    msg
}

#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    NxDomain,
    A(Ipv4Addr),
}

fn query(server: SocketAddr, domain: &str) -> io::Result<Answer> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let req = build_query(0x1234, domain);
    socket.send_to(&req, server)?;
    let mut buf = [0u8; 512];
    let len = socket.recv(&mut buf)?;
    let msg = &buf[..len];
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let rcode = flags & 0x000F;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    if rcode == 3 || ancount == 0 {
        return Ok(Answer::NxDomain);
    }
    // Skip header (12) + question (qname + qtype + qclass), then the
    // answer's compressed name pointer (2 bytes) + type/class/ttl/rdlength (10).
    let (_qname, qend) = parse_name(msg, 12).ok_or_else(bad_reply)?;
    let ans_start = qend + 4;
    let rdata_start = ans_start + 2 + 10;
    let ip = Ipv4Addr::new(
        *msg.get(rdata_start).ok_or_else(bad_reply)?,
        *msg.get(rdata_start + 1).ok_or_else(bad_reply)?,
        *msg.get(rdata_start + 2).ok_or_else(bad_reply)?,
        *msg.get(rdata_start + 3).ok_or_else(bad_reply)?,
    );
    Ok(Answer::A(ip))
}

fn bad_reply() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed DNS reply")
}

/// Asserts `domain` is sinkholed (NXDOMAIN) by the resolver at `server`.
pub fn assert_sinkholed(server: SocketAddr, domain: &str) {
    match query(server, domain) {
        Ok(Answer::NxDomain) => {}
        Ok(Answer::A(ip)) => panic!("expected {domain} to be sinkholed, got A {ip}"),
        Err(e) => panic!("query for {domain} failed: {e}"),
    }
}

/// Asserts `domain` resolves to `expected` via the resolver at `server`.
pub fn assert_resolves(server: SocketAddr, domain: &str, expected: Ipv4Addr) {
    match query(server, domain) {
        Ok(Answer::A(ip)) if ip == expected => {}
        Ok(Answer::A(ip)) => panic!("expected {domain} -> {expected}, got {ip}"),
        Ok(Answer::NxDomain) => panic!("expected {domain} to resolve, got NXDOMAIN"),
        Err(e) => panic!("query for {domain} failed: {e}"),
    }
}
