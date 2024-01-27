from __future__ import annotations
import pytest
from cryptocerts.certificates import (
    CertificateToken,
    TrustedCertificateStore,
    CertificateVerifier,
    IntermediaryCertificateStore,
)
from .utils import load_from_file


@pytest.fixture
def root_certificate_token() -> CertificateToken:
    return CertificateToken(load_from_file("oz/root.crt"))


@pytest.fixture
def intermediate_certificate_token() -> CertificateToken:
    return CertificateToken(load_from_file("oz/intermediate.crt"))


@pytest.fixture
def leaf_certificate_token() -> CertificateToken:
    return CertificateToken(load_from_file("oz/leaf.crt"))


@pytest.fixture
def certificate_verifier(
    root_certificate_token: CertificateToken,
    intermediate_certificate_token: CertificateToken,
):
    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)

    intermediary_store = IntermediaryCertificateStore()
    intermediary_store.add_certificate(intermediate_certificate_token)

    certificate_verifier = CertificateVerifier(
        trusted_store=trusted_store, intermediary_store=intermediary_store
    )

    return certificate_verifier
