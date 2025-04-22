use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::log::log_trace;
use crate::types::*;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CacheKey {
    pub sni: String,
    pub record_type: RecordType,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub addresses: Vec<IpAddr>,
    pub expired_at: Instant,
}

pub struct DnsQueryCache {
    cache: HashMap<CacheKey, CacheEntry>,
}

impl DnsQueryCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
    pub fn get(&mut self, key: &CacheKey) -> Option<CacheEntry> {
        log_trace(&format!(
            "DnsQueryCache.get({:?}), cache: {:?}",
            key, self.cache
        ));
        match self.cache.get(key) {
            None => None,
            Some(val) => {
                if val.expired_at < Instant::now() {
                    // cache was expired
                    self.cache.remove(key);
                    None
                } else {
                    Some(val.clone())
                }
            }
        }
    }
    pub fn set(&mut self, key: CacheKey, val: DnsResponse) -> Option<CacheEntry> {
        log_trace(&format!(
            "DnsQueryCache.set({:?} = {:?}), cache: {:?}",
            key, val, self.cache
        ));
        // DEBUG
        log_trace(&format!(
            "answers: {:?}, min_ttl: {:?}",
            val.answers,
            val.answers.iter().map(|a| a.ttl).min()?
        ));

        self.cache.insert(
            key,
            CacheEntry {
                addresses: val.answers.iter().map(|a| a.ip).collect(),
                expired_at: Instant::now()
                    + Duration::from_secs(From::from(val.answers.iter().map(|a| a.ttl).min()?)),
            },
        )
    }
}
