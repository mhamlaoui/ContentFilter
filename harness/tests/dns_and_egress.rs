use cf_test_harness::dns::{assert_resolves, assert_sinkholed, DnsFixture, Outcome};
use cf_test_harness::egress::{assert_egress_allowed, assert_egress_denied, block_outbound_tcp};
use std::collections::HashMap;
use std::net::{Ipv4Addr, TcpListener};

#[test]
fn blocked_domain_is_sinkholed_and_allowed_domain_resolves() {
    let mut records = HashMap::new();
    records.insert("blocked.test".to_string(), Outcome::Sinkhole);
    records.insert(
        "allowed.test".to_string(),
        Outcome::Resolve(Ipv4Addr::new(93, 184, 216, 34)),
    );
    let fixture = DnsFixture::start(records).expect("start DNS fixture");

    assert_sinkholed(fixture.addr(), "blocked.test");
    assert_resolves(
        fixture.addr(),
        "allowed.test",
        Ipv4Addr::new(93, 184, 216, 34),
    );
}

#[test]
fn egress_port_is_denied_once_blocked() {
    if std::env::var_os("CI").is_none() {
        eprintln!("skipping: modifies OS firewall state, only runs in CI");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind egress-target listener");
    let addr = listener.local_addr().unwrap();

    assert_egress_allowed(addr);

    let guard = block_outbound_tcp(addr.port()).expect("apply firewall rule");
    assert_egress_denied(addr);

    drop(guard);
    assert_egress_allowed(addr);
}
