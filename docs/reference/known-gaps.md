# Known gaps

- **OS TUN mode and the Linux subnet router have not been run on real machines.** Userspace mode is covered by end-to-end tests. The Windows service and installer are also untested on real PCs.
- **The Windows installer isn't code-signed**, so Windows SmartScreen warns about an unknown publisher (More info → Run anyway). Signing needs a code-signing certificate.
- **Exit nodes**: the exit side (forwarding + NAT) is Linux-only. On macOS, DNS lookups don't go through the exit node yet.
- Subnet routing is Linux-only for now.
- Machine keys live in a file (protected, but not in a TPM or secure enclave): whoever copies a machine's whole state can still act as it until it's removed. See the [security review](security-review.md) for the threat model and other residual risks.
