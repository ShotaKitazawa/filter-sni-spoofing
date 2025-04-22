use serde::Deserialize;

pub const DEFAULT_FAILURE_POLICY: FailurePolicy = FailurePolicy::Fail;

#[derive(Debug, Clone, Deserialize)]
pub struct FilterConfig {
    pub dns_server_hostname: String,
    pub dns_server_cluster_name: String,
    pub failure_policy: Option<FailurePolicy>,
}

#[derive(Debug, Clone, Deserialize)]
pub enum FailurePolicy {
    Ignore, // Fail-open
    Fail,   // Fail-closed
}
