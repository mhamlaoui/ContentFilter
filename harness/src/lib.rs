//! Enforcement integration-test harness: DNS sinkhole and egress-deny
//! assertion helpers used to prove filtering behavior end to end.
//!
//! The fixtures here are stand-ins for `svc-resolver` and `svc-egress-wfp`.
//! Once those ship, point [`dns::assert_sinkholed`] and friends at the real
//! service instead of [`dns::DnsFixture`], and swap [`egress::block_outbound_tcp`]
//! for asserting the service's own WFP filters are in place.

pub mod dns;
pub mod egress;
