# VULN-711: CA trust remediation

This patch changes build inputs. It does not merge, publish an image, release a
binary, start a Grafana client, or authorize deployment. Application requires
customer, operations and development agreement; the responsible owner records
that decision separately in VULN-711.

- Go 1.26.10 is the same-minor security patch for crypto/x509. `go.mod`, both
  Docker builders, test CI and release CI select this minimum consistently.
- Debian 12 build/final CA packages must be at least `20250419~deb12u2`.
- Alpine 3.23 build/final CA packages must be at least `20261020-r0`.
- Python E2E uses certifi 2026.10.23 with a `>=2026.10.19` floor, uv 0.13.4 and
  locked dependency installation. Other locked package resolutions are unchanged.
- The dedicated PR check builds fresh images without registry push. It runs the
  application `--help` and the same `BuildTransport` TLS path against 14 public
  incident chains and three normal public endpoints. It needs no Grafana or LLM
  credentials. It also checks certifi as an explicit CA bundle. Full LLM/cloud
  integration tests remain separate because they require service credentials.

Existing Dependabot PR #22 overlaps the certifi lock update. This consolidated
patch includes the additional Go, OS CA and build verification paths. Reviewers
should select the consolidated change without merging the stale lock update
again. PR #2's SSO implementation and branch are unchanged.

References:
- https://go.dev/doc/devel/release
- https://packages.debian.org/bookworm/ca-certificates
- https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/ca-certificates
- https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
