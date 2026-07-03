# cf-test-harness

Enforcement integration-test helpers: DNS sinkhole/resolve assertions and
real (temporary) egress-firewall-rule assertions. See `src/dns.rs` and
`src/egress.rs` for the fixtures, and `tests/dns_and_egress.rs` for the
sample test required by `f-test-harness`.

These are stand-ins for `svc-resolver` and `svc-egress-wfp`, which don't
exist yet. Once they do, point the same `assert_sinkholed` /
`assert_resolves` / `assert_egress_denied` / `assert_egress_allowed` helpers
at the real service instead of `DnsFixture` / `block_outbound_tcp`.

## Running locally

`cargo test -p cf-test-harness` runs the DNS fixture test unconditionally
(it only binds loopback UDP sockets, nothing system-wide). The egress test
skips itself unless the `CI` environment variable is set, because it
modifies real OS firewall state — don't set `CI=true` locally unless you
mean to let it add and remove a real firewall rule on your machine.

## Windows runner path

On `windows-latest` GitHub-hosted runners, the default account can run
`netsh advfirewall firewall add/delete rule` non-interactively (no UAC
prompt blocks Actions steps). `CI` is set by GitHub Actions automatically,
so the egress test runs for real there. If you move this to a self-hosted
Windows runner, confirm the service account has local admin rights, or the
`netsh` calls in `src/egress.rs` will fail with a permissions error rather
than silently passing.

Confirmed empirically in CI: a live same-host connection attempt cannot
prove Windows outbound blocking, even against a real (non-loopback)
interface address — Windows appears to route same-host TCP through a fast
path that bypasses the filter regardless of a correctly-scoped, verified
`Action: Block` rule being active. `tests/dns_and_egress.rs` therefore
verifies the rule's own state via `rule_blocks_port` on Windows instead of
attempting a live connection. Linux's `iptables OUTPUT` chain doesn't have
this problem, so the Linux path uses the real connection-based assertion.
When `svc-egress-wfp` exists for real, re-evaluate whether this limitation
still applies to its actual WFP callout (it may not, since ALE callouts can
differ from userspace firewall rules).

On `ubuntu-latest`, the equivalent path uses `sudo iptables`; GitHub-hosted
Ubuntu runners have passwordless sudo for the default user.
