# ADR-0115: Opt-in OpenSSL cipher string for the client TLS context

- **Date:** 2026-10-24
- **Status:** Accepted
- **Deciders:** agent session, from an operator request to register against gateways
  that only offer TLS 1.2 static-RSA `AES256-GCM-SHA384`.

## Context

`_make_tls_context` (`src/hermes_voip/adapter.py`) builds the sole client TLS
context for both signalling legs, SIP-over-TLS and WSS (ADR-0089). ADR-0089 floors
that context at TLS 1.2 and leaves `check_hostname` and `CERT_REQUIRED` inherited
from `ssl.create_default_context()`.

On Python 3.13 / OpenSSL 3.5 that default cipher list is forward-secret only:
TLS 1.3 suites plus ECDHE/DHE. It does not offer the TLS 1.2 static-RSA suite
`AES256-GCM-SHA384` (`TLS_RSA_WITH_AES_256_GCM_SHA384`). Some VoIP.ms international
points of presence (`amsterdam1.voip.ms`, `london1.voip.ms`, `paris1.voip.ms`,
port 5061) accept only that suite. The handshake then fails with
`SSLV3_ALERT_HANDSHAKE_FAILURE` (alert 40). An out-of-tree probe that called
`SSLContext.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:AES256-GCM-SHA384")` completed
registration, negotiated TLSv1.2 `AES256-GCM-SHA384`, and kept the TLS 1.2 minimum,
`CERT_REQUIRED`, and hostname checks.

Static RSA has no forward secrecy. A later compromise of the server private key can
decrypt recorded handshakes. The default must stay forward-secret for every
deployment that does not need the suite.

## Decision

`HERMES_SIP_TLS_CIPHERS`, when set, is an OpenSSL cipher string stored on
`GatewayConfig.tls_ciphers` and applied with `SSLContext.set_ciphers` inside
`_make_tls_context`. When the variable is unset or blank, `set_ciphers` is not
called and the context matches today's default.

The cipher string cannot weaken the signalling leg:

- After `set_ciphers`, the builder sets `minimum_version` back to TLS 1.2,
  `check_hostname` back to `True`, and `verify_mode` back to `CERT_REQUIRED`.
- A string OpenSSL cannot apply (`SSLError` from `set_ciphers`, including
  "No cipher can be selected.") raises `ConfigError` naming
  `HERMES_SIP_TLS_CIPHERS` at `GatewayConfig` construction, which is startup.
- A string that lowers `SSLContext.security_level` below
  `ssl.create_default_context()` (for example `@SECLEVEL=0`) is rejected the same
  way. Dropping the security level would admit weaker certificates and algorithms
  while `CERT_REQUIRED` stayed set.

The string is not a secret. It is documented in the README, `.env.example`, and
both `plugin.yaml` manifests. No new resource is provisioned, so no runbook
procedure changes beyond naming the variable next to the other optional
`HERMES_SIP_*` keys.

## Consequences

- Operators who need TLS 1.2 static RSA can register by setting the cipher string.
  They accept the loss of forward secrecy on that signalling leg, which also
  carries the SIP digest material and any SDES key.
- Every other deployment keeps the forward-secret default. Adding the field does
  not change an existing context's cipher list, version floor, or verification.
- SIP-over-TLS and WSS share the one context, so a set string applies to both.
- Future changes to `_make_tls_context` must keep the three floors and must not
  call `set_ciphers` unless this setting is present. A cipher string must still
  be rejected when it lowers `security_level`.
- `tests/test_config.py` covers unset, blank, stored, invalid, and security-level
  downgrade at config validation. `tests/test_adapter_tls_context.py` covers the
  built context: default cipher list unchanged, the string applied (including
  `AES256-GCM-SHA384`), and the floors still pinned.

## Alternatives considered

| Alternative | Rejected because |
| --- | --- |
| Add `AES256-GCM-SHA384` to the default cipher list | Every deployment would offer a non-forward-secret suite, including gateways that negotiate ECDHE today. The default stays forward-secret. |
| Cap `maximum_version` at TLS 1.2 | The probe registered while TLS 1.3 was still offered; the server selected TLS 1.2. Capping the maximum would drop TLS 1.3 for gateways that prefer it. |
| `set_ciphersuites` (TLS 1.3) instead of `set_ciphers` | The missing suite is a TLS 1.2 static-RSA suite. `set_ciphersuites` does not offer it. |
| A built-in provider preset that names VoIP.ms | Hard-codes one provider into a gateway-agnostic plugin. An operator-supplied OpenSSL cipher string is the explicit opt-in. |
| Honour `@SECLEVEL` inside the cipher string | `@SECLEVEL=0` drops `security_level` from 2 to 0 and admits weaker certificates while `CERT_REQUIRED` stays set. That weakens verification, so those strings are rejected. |
