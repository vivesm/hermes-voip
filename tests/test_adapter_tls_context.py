"""TLS-context hardening for the SOLE client TLS context (ADR-0089, ADR-0005).

``_make_tls_context`` builds the only client TLS context for BOTH the
SIP-over-TLS and WSS signalling legs — the legs that carry the SIP digest
password (Authorization HA1/response) and the SDES ``a=crypto`` inline master
key and salt. A bare ``ssl.create_default_context()`` leaves
``minimum_version`` at ``TLSVersion.MINIMUM_SUPPORTED`` on Python 3.13, so the
host OpenSSL policy could negotiate TLS 1.0/1.1 on those secret-bearing legs.
This module pins the TLS 1.2 floor and locks the inherited verification posture
(``check_hostname`` / ``CERT_REQUIRED``) so a future weakening is caught.

The adapter imports the real Hermes base at module top, so importing
``_make_tls_context`` needs the optional ``hermes`` extra; the module skips
cleanly without it and runs in the ``hermes-contract`` CI job (rule 26). The
test asserts context PROPERTIES only — no live connection, no real host or
certificate (public repo).
"""

from __future__ import annotations

import ssl

import pytest

# The adapter imports the real Hermes base at module top; skip the whole module
# when the optional runtime is absent (it runs in the hermes-contract CI job).
pytest.importorskip("gateway.platforms.base")
pytest.importorskip("gateway.config")

from hermes_voip.adapter import _make_tls_context
from hermes_voip.config import ConfigError

# The string an out-of-tree probe used to offer TLS 1.2 static-RSA
# AES256-GCM-SHA384 alongside the forward-secret AEAD suites. No hostname.
_TLS12_STATIC_RSA_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:AES256-GCM-SHA384"


def _cipher_names(ctx: ssl.SSLContext) -> list[str]:
    return [cipher["name"] for cipher in ctx.get_ciphers()]


def _default_client_context() -> ssl.SSLContext:
    """The context ``_make_tls_context`` builds when no cipher string is set."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _assert_tls_floors(ctx: ssl.SSLContext) -> None:
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_make_tls_context_pins_min_version_and_verification() -> None:
    """The client TLS context floors at TLS 1.2 and keeps verification on."""
    ctx = _make_tls_context("pbx.example.test")

    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2, (
        "the client TLS context must floor at TLS 1.2 to prevent downgrade to "
        "TLS 1.0/1.1 on the leg carrying the digest password and SDES key"
    )
    assert ctx.check_hostname is True, (
        "server-certificate hostname verification must stay enabled "
        "(downgrade-hardening is not a verification bypass)"
    )
    assert ctx.verify_mode == ssl.CERT_REQUIRED, (
        "server-certificate verification must stay required"
    )


def test_make_tls_context_unset_keeps_the_default_cipher_list() -> None:
    """No cipher string means set_ciphers is not called."""
    ctx = _make_tls_context("pbx.example.test")
    baseline = _default_client_context()
    assert _cipher_names(ctx) == _cipher_names(baseline)
    assert ctx.security_level == baseline.security_level
    _assert_tls_floors(ctx)


def test_make_tls_context_applies_cipher_string_without_weakening_floors() -> None:
    """A set cipher string is applied, and the TLS floors stay pinned."""
    ctx = _make_tls_context("pbx.example.test", tls_ciphers=_TLS12_STATIC_RSA_CIPHERS)
    expected = _default_client_context()
    expected.set_ciphers(_TLS12_STATIC_RSA_CIPHERS)
    names = _cipher_names(ctx)
    assert names == _cipher_names(expected)
    assert names != _cipher_names(_default_client_context())
    assert "AES256-GCM-SHA384" in names
    assert ctx.security_level == _default_client_context().security_level
    _assert_tls_floors(ctx)


def test_make_tls_context_rejects_unusable_cipher_string() -> None:
    """An unusable cipher string fails clearly instead of building a context."""
    with pytest.raises(ConfigError, match="HERMES_SIP_TLS_CIPHERS") as raised:
        _make_tls_context("pbx.example.test", tls_ciphers="NO-SUCH-CIPHER")
    assert isinstance(raised.value.__cause__, ssl.SSLError)
    _assert_tls_floors(_make_tls_context("pbx.example.test"))


def test_make_tls_context_rejects_security_level_downgrade() -> None:
    """A cipher string cannot drop the OpenSSL security level."""
    with pytest.raises(ConfigError, match="security level"):
        _make_tls_context(
            "pbx.example.test",
            tls_ciphers="@SECLEVEL=0:AES256-GCM-SHA384",
        )
