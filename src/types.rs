use std::net::IpAddr;

// DNS Record Types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A = 1,
    AAAA = 28,
}
impl From<RecordType> for u16 {
    fn from(record_type: RecordType) -> Self {
        record_type as u16
    }
}
impl From<&IpAddr> for RecordType {
    fn from(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::AAAA,
        }
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::AAAA => write!(f, "AAAA"),
        }
    }
}

// DNS wire format関連の関数と構造体
pub struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHeader {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            flags: 0x0100, // 標準的なクエリ、再帰的な解決を要求
            qdcount: 1,    // 1つのクエリ
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        bytes.extend_from_slice(&self.ancount.to_be_bytes());
        bytes.extend_from_slice(&self.nscount.to_be_bytes());
        bytes.extend_from_slice(&self.arcount.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub ip: IpAddr,
    pub ttl: u32,
}
