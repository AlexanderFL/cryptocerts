from __future__ import annotations

from datetime import datetime

import pytest
from freezegun import freeze_time

from cryptocerts import CertificateToken
from cryptocerts.exceptions import CertificateAlreadyStored, InvalidChain
from cryptocerts.paths import CertificatePathBuilder
from cryptocerts.stores import (
    CertificatesStore,
    IntermediaryCertificateStore,
    TrustedCertificateStore,
)
from cryptocerts.validators import CertificateValidator
from cryptocerts.validators.enums import ValidationStatus, ValidatorErrors

from ..utils import load_from_file


def test_certificate_verifier_initialize_empty():
    """
    Tests that a certificate verifier can be initialized with an empty store.
    """
    certificate_verifier = CertificateValidator()

    assert isinstance(certificate_verifier, CertificateValidator)
    assert isinstance(certificate_verifier.certificates_store, CertificatesStore)
    assert isinstance(certificate_verifier.certificate_path_builder, CertificatePathBuilder)


def test_certificate_verifier_initialize_minimal(certificates_store: CertificatesStore):
    """
    Tests that a certificate verifier can be initialized with an minimal store.
    """
    certificate_verifier = CertificateValidator(certificates_store)

    assert isinstance(certificate_verifier, CertificateValidator)


@freeze_time(datetime(2024, 1, 28, 20, 0, 0))
def test_certificate_verifier_verify_leaf_certificate(
    certificate_verifier: CertificateValidator, leaf_certificate_token: CertificateToken
):
    """
    Tests that a certificate verifier can verify a leaf certificate.
    """
    result = certificate_verifier.validate_certificate(leaf_certificate_token)

    assert result.validation_conclusion == ValidationStatus.VALID
    assert result.valid_to_trusted_root is True


@freeze_time(datetime(2024, 1, 28, 20, 0, 0))
def test_certificate_verifier_verify_intermediate_certificate(
    certificate_verifier: CertificateValidator,
    intermediate_certificate_token: CertificateToken,
):
    """
    Tests that a certificate verifier can verify an intermediate certificate.
    """
    result = certificate_verifier.validate_certificate(intermediate_certificate_token)

    assert result.valid_to_trusted_root is True


@freeze_time(datetime(2024, 1, 28, 20, 0, 0))
def test_certificate_verifier_verify_root_certificate(
    certificate_verifier: CertificateValidator, root_certificate_token: CertificateToken
):
    """
    Tests that a certificate verifier can verify a root certificate.
    """
    result = certificate_verifier.validate_certificate(root_certificate_token)

    assert result.valid_to_trusted_root is True


@freeze_time(datetime(2024, 1, 28, 20, 0, 0))
def test_certificate_verifier_pkcs7_verify_leaf_certificate(
    certificate_verifier: CertificateValidator,
):
    """
    Tests that a certificate verifier can verify a leaf certificate using PKCS7.
    """
    certificate = CertificateToken(load_from_file("cloudflare/developers.cloudflare_pkcs7.p7b"))
    result = certificate_verifier.validate_certificate(certificate)

    assert result.valid_to_trusted_root is False
    assert result.validation_conclusion == ValidationStatus.INVALID
