use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod log;
use crate::log::{log_debug, log_error, log_trace};
mod config;
use crate::config::{FailurePolicy, FilterConfig, DEFAULT_FAILURE_POLICY};
mod types;
use crate::types::*;
mod cache;
use crate::cache::{CacheKey, DnsQueryCache};

struct FilterImpersonatedSniRoot {
    config: Option<FilterConfig>,
    cache: Arc<Mutex<DnsQueryCache>>,
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
       Box::new(FilterImpersonatedSniRoot {
            config: None,
             cache: Arc::new(Mutex::new(DnsQueryCache::new())),
        })
    });
}}

impl Context for FilterImpersonatedSniRoot {}

impl RootContext for FilterImpersonatedSniRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            match serde_json::from_slice::<FilterConfig>(&config_bytes) {
                Ok(config) => {
                    log_debug(&format!("Loaded configuration: {:?}", config));
                    self.config = Some(config);
                    true
                }
                Err(e) => {
                    log_error(&format!("Failed to parse configuration: {}", e));
                    false
                }
            }
        } else {
            log_error("No configuration provided");
            false
        }
    }

    fn create_stream_context(&self, _: u32) -> Option<Box<dyn StreamContext>> {
        match &self.config {
            Some(config) => Some(Box::new(FilterImpersonatedSni {
                config: config.clone(),
                cache: Arc::clone(&self.cache),
            })),
            None => None,
        }
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::StreamContext)
    }
}

struct FilterImpersonatedSni {
    config: FilterConfig,
    cache: Arc<Mutex<DnsQueryCache>>,
}

impl Context for FilterImpersonatedSni {
    fn on_http_call_response(&mut self, token_id: u32, _: usize, body_size: usize, _: usize) {
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            match self.parse_dns_response(&body) {
                Ok(response) => {
                    log_debug(&format!(
                        "Received DoH response with {} answers",
                        response.answers.len()
                    ));
                    return self.handle_dns_response(token_id, response);
                }
                Err(e) => {
                    log_error(&format!("Failed to parse DNS response: {}", e));
                }
            }
        } else {
            log_error("Empty DoH response");
        }
        self.close_downstream();
    }
}

impl StreamContext for FilterImpersonatedSni {
    fn on_new_connection(&mut self) -> Action {
        // Get SNI and destination IP
        if let Some(dst_ip) = self.get_destination_ip() {
            log_trace(&format!("Destination IP: {}", dst_ip));
            if let Some(sni_str) = self.get_sni() {
                log_trace(&format!("SNI: {}", sni_str));
                return self.verify_sni_matches_ip(&sni_str, &dst_ip);
            } else {
                // If get_sni is failed, protocol may not be HTTPS
                log_debug("Could not get SNI, then following failure policy");
                self.follow_failure_policy();
                Action::Continue
            }
        } else {
            // If get_destination_ip is failed, something was wrong.
            log_debug("Could not get destination_ip, then denying connection");
            self.close_downstream();
            Action::Continue
        }
    }
}

impl FilterImpersonatedSni {
    fn get_destination_ip(&self) -> Option<IpAddr> {
        let property = self.get_property(vec!["destination", "address"])?;
        let addr_str = String::from_utf8(property).ok()?;
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            Some(addr.ip())
        } else {
            log_error(&format!("{} is not a format of IpAddr", addr_str));
            None
        }
    }

    fn get_sni(&self) -> Option<String> {
        let property = self.get_property(vec!["connection", "requested_server_name"])?;
        String::from_utf8(property).ok()
    }

    fn verify_sni_matches_ip(&mut self, sni: &str, ip: &IpAddr) -> Action {
        // Determine if IP is IPv4 or IPv6
        let record_type = RecordType::from(ip);

        // Check cache first
        let cache_key = CacheKey {
            sni: sni.to_string(),
            record_type,
        };
        if let Some(entry) = self.cache.lock().unwrap().get(&cache_key) {
            log_debug(&format!(
                "Cache hit for {}, record type: {}",
                sni, record_type
            ));
            match entry.addresses.contains(ip) {
                true => self.resume_downstream(),
                false => self.close_downstream(),
            };
            return Action::Continue;
        } else {
            log_debug(&format!(
                "Cache miss for {}, record type: {}",
                sni, record_type
            ));
        }

        // Query DoH server
        match self.query_doh_server(sni, record_type) {
            Ok(action) => action,
            Err(str) => {
                log_error(&str);
                self.follow_failure_policy();
                Action::Continue
            }
        }
    }

    fn query_doh_server(&mut self, sni: &str, record_type: RecordType) -> Result<Action, String> {
        // headers that conform to RFC 8484.
        let headers = vec![
            ("content-type", "application/dns-message"),
            (":authority", &self.config.dns_server_hostname),
            (":method", "POST"),
            (":path", "/dns-query"),
        ];
        // body is DNS wire format that conforms to RFC 1035
        let body = &self.create_dns_query(sni, record_type);

        match self.dispatch_http_call(
            &self.config.dns_server_cluster_name,
            headers,
            Some(body),
            vec![],
            Duration::from_secs(5),
        ) {
            Ok(token) => {
                log_debug(&format!("Dispatched DoH request with token: {}", token));
                return Ok(Action::Pause);
            }
            Err(e) => {
                return Err(format!("Failed to dispatch DoH request: {:?}", e));
            }
        }
    }

    // create_dns_query constructs request body for DNS wire format [RFC 1035]
    fn create_dns_query(&self, domain: &str, record_type: RecordType) -> Vec<u8> {
        let mut query = Vec::new();

        // DNS Header
        let header = DnsHeader::new(0x1234); // TODO: random ID
        query.extend_from_slice(&header.to_bytes());

        // encoded domain name
        let labels: Vec<&str> = domain.split('.').collect();
        for label in labels {
            if label.is_empty() {
                continue;
            }
            let len = label.len() as u8;
            query.push(len);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0); // end of domain name

        // query type
        let qtype = u16::from(record_type);
        query.extend_from_slice(&qtype.to_be_bytes());

        // query class (IN=1)
        query.extend_from_slice(&(1u16).to_be_bytes());

        query
    }

    // parse_dns_response parses the response from DoH server
    // The reference of the format for DNS response: rfc1035#section-4
    fn parse_dns_response(&self, response: &[u8]) -> Result<DnsResponse, String> {
        if response.len() < 12 {
            return Err("Response too short".to_string());
        }
        let mut answers = Vec::new();

        //
        // Parse Header section
        //
        let qdcount = u16::from_be_bytes([response[4], response[5]]);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            return Ok(DnsResponse { answers });
        }

        //
        // Parse Question section
        // MEMO: skipped Question section in this implementation
        //
        let mut pos = 12;
        for _ in 0..qdcount {
            // skip QNAME
            while pos < response.len() {
                let len = response[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                pos += len + 1;
            }
            // skip QTYPE & QCLASS
            pos += 4;
        }

        //
        // Parse Answer section
        //
        for _ in 0..ancount {
            if pos + 12 >= response.len() {
                break;
            }
            // skip NAME
            if (response[pos] & 0xC0) == 0xC0 {
                // if message is compressed
                pos += 2;
            } else {
                while pos < response.len() {
                    let len = response[pos] as usize;
                    if len == 0 {
                        pos += 1;
                        break;
                    }
                    pos += len + 1;
                }
            }

            //
            // Parse Answer section - TYPE, CLASS, TTL, RDLENGTH
            //

            // 10 bytes = TYPE + CLASS + TTL + RDLENGTH
            if pos + 10 >= response.len() {
                break;
            }

            let record_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
            pos += 4; // TYPE + CLASS

            let ttl = u32::from_be_bytes([
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3],
            ]);
            pos += 4; // TTL

            let rdlength = u16::from_be_bytes([response[pos], response[pos + 1]]) as usize;
            pos += 2; // RDLENGTH

            //
            // Parse Answer section - RDATA
            //

            if pos + rdlength > response.len() {
                break;
            }
            if (record_type == 1 && rdlength == 4) || (record_type == 28 && rdlength == 16) {
                let ip = if record_type == 1 {
                    // for A record
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        response[pos],
                        response[pos + 1],
                        response[pos + 2],
                        response[pos + 3],
                    ))
                } else {
                    // for AAAA record
                    let mut ipv6_bytes = [0u8; 16];
                    ipv6_bytes.copy_from_slice(&response[pos..pos + 16]);
                    IpAddr::V6(std::net::Ipv6Addr::from(ipv6_bytes))
                };

                answers.push(DnsAnswer { ip, ttl });
            }

            pos += rdlength;
        }

        Ok(DnsResponse { answers })
    }

    fn handle_dns_response(&mut self, _token_id: u32, response: DnsResponse) {
        if response.answers.is_empty() {
            log_debug("No addresses found in DNS response");
            self.close_downstream();
            return;
        }

        // Get SNI and destination IP again
        if let Some(dst_ip) = self.get_destination_ip() {
            if let Some(sni_str) = self.get_sni() {
                // update cache
                self.cache.lock().unwrap().set(
                    CacheKey {
                        sni: sni_str,
                        record_type: RecordType::from(&dst_ip),
                    },
                    response.clone(),
                );

                let addresses = &response
                    .answers
                    .iter()
                    .map(|answer| answer.ip)
                    .collect::<Vec<IpAddr>>();
                match addresses.contains(&dst_ip) {
                    true => self.resume_downstream(),
                    false => self.close_downstream(),
                }
                return;
            }
        }

        // If we can't get SNI or destination IP, something was wrong.
        log_debug("Could not get SNI or destination IP in response handler, denying connection");
        self.close_downstream();
    }

    fn follow_failure_policy(&self) {
        match self
            .config
            .failure_policy
            .clone()
            .unwrap_or(DEFAULT_FAILURE_POLICY)
        {
            FailurePolicy::Ignore => self.resume_downstream(),
            FailurePolicy::Fail => self.close_downstream(),
        }
    }

    #[cfg(test)]
    fn dispatch_http_call(
        &self,
        upstream: &str,
        headers: Vec<(&str, &str)>,
        body: Option<&[u8]>,
        trailers: Vec<(&str, &str)>,
        timeout: Duration,
    ) -> Result<u32, Status> {
        log_debug("--- dispatch_http_call ---");
        log_debug(&format!("upstream: {}", upstream));
        log_debug(&format!("headers: {:?}", headers));
        log_debug(&format!("body: {:?}", body));
        log_debug(&format!("trailers: {:?}", trailers));
        log_debug(&format!("timeout: {:?}", timeout));
        log_debug("------");
        return Ok(0);
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::DnsQueryCache;
    use crate::config::{FailurePolicy, FilterConfig};
    use crate::{FilterImpersonatedSni, RecordType};
    use proxy_wasm::types::Action;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_query_doh_server() {
        let mut m = FilterImpersonatedSni {
            config: FilterConfig {
                dns_server_hostname: String::from("dns-server.local"),
                dns_server_cluster_name: String::from("dns-server"),
                failure_policy: Some(FailurePolicy::Fail),
            },
            cache: Arc::new(Mutex::new(DnsQueryCache::new())),
        };
        let action = m.query_doh_server("s1.local", RecordType::A);
        assert_eq!(action, Ok(Action::Pause));
    }
}
