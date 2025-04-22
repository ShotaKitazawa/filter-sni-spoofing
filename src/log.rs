use proxy_wasm::types::LogLevel;

#[allow(dead_code)]
pub fn log_error(message: &str) {
    log(LogLevel::Error, message);
}

#[allow(dead_code)]
pub fn log_info(message: &str) {
    log(LogLevel::Info, message);
}

#[allow(dead_code)]
pub fn log_debug(message: &str) {
    log(LogLevel::Debug, message);
}

#[allow(dead_code)]
pub fn log_trace(message: &str) {
    //log(LogLevel::Trace, message);
    log(LogLevel::Debug, message);
}

#[allow(clippy::print_with_newline)]
fn log(level: LogLevel, message: &str) {
    #[cfg(not(test))]
    let _ = proxy_wasm::hostcalls::log(level, message);
    #[cfg(test)]
    print!(">>> level: {:?}, message: {}\n", level, message)
}
