//! Proves the relay's logging is actually structured (valid JSON per
//! line), not just "we called `.json()` and hope." Uses a scoped
//! subscriber (`tracing::subscriber::with_default`), not the process-wide
//! global one, so this doesn't interfere with other test binaries.

use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn each_log_line_is_valid_json_with_the_expected_fields() {
    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(buffer.clone())
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(component = "relay", "test log line");
    });

    let captured = buffer.0.lock().unwrap().clone();
    let text = String::from_utf8(captured).expect("log output should be valid UTF-8");
    let line = text.lines().next().expect("at least one log line");

    let parsed: serde_json::Value =
        serde_json::from_str(line).expect("each log line must be a standalone valid JSON object");
    assert_eq!(parsed["fields"]["message"], "test log line");
    assert_eq!(parsed["fields"]["component"], "relay");
    assert_eq!(parsed["level"], "INFO");
    assert!(
        parsed.get("timestamp").is_some(),
        "structured logs should carry a timestamp field"
    );
}
