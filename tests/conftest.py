from __future__ import annotations

import pytest

from cryptocerts import CertificateToken
from cryptocerts.stores import (
    CertificatesStore,
    IntermediaryCertificateStore,
    TrustedCertificateStore,
)
from cryptocerts.validators import CertificateValidator

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
def certificates_store(
    root_certificate_token: CertificateToken, intermediate_certificate_token: CertificateToken
) -> CertificatesStore:

    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)

    intermediate_store = IntermediaryCertificateStore()
    intermediate_store.add_certificate(intermediate_certificate_token)

    return CertificatesStore(trusted_store=trusted_store, intermediate_store=intermediate_store)


@pytest.fixture
def certificate_verifier(certificates_store: CertificatesStore):
    certificate_verifier = CertificateValidator(certificates_store)

    return certificate_verifier
