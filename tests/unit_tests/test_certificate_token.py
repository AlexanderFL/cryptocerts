from __future__ import annotations

import os

from cryptography import x509

from cryptocerts import CertificateToken

from ..utils import load_from_file


def test_certificate_token_initialize_x509_pem():
    """
    Tests that a certificate token can be initialized with an x509 certificate in PEM format.
    """
    google_bytes = load_from_file("google/google.pem")
    certificate_token = CertificateToken(google_bytes)

    assert isinstance(certificate_token, CertificateToken)


def test_certificate_token_initialize_x509_der():
    """
    Tests that a certificate token can be initialized with an x509 certificate in DER format.
    """
    google_bytes = load_from_file("google/google.der")
    certificate_token = CertificateToken(google_bytes)

    assert isinstance(certificate_token, CertificateToken)


def test_certificate_token_initialize_x509_pem_chain():
    """
    Tests that a certificate token can be initialized with an x509 certificate in PEM format with a chain.
    """
    google_bytes = load_from_file("google/google_chain.pem")
    certificate_token = CertificateToken(google_bytes)

    assert len(certificate_token.chain) == 2
    assert isinstance(certificate_token, CertificateToken)


def test_certificate_token_initialize_pkcs7_p7c():
    """
    Tests that a certificate token can be initialized with a PKCS7 certificate in P7C format.
    """
    google_bytes = load_from_file("google/google.p7c")
    certificate_token = CertificateToken(google_bytes)

    assert isinstance(certificate_token, CertificateToken)


def test_certificate_load_from_file():
    """
    Tests that a certificate can be loaded from a file.
    """
    # TODO: Find a better way to do this.
    filename = "google/google.pem"
    filepath = os.path.dirname(__file__)
    full_path = os.path.join(filepath, "../repository", filename)

    certificate_token = CertificateToken.load_from_file(full_path)

    assert isinstance(certificate_token, CertificateToken)


def test_certificate_token_is_self_signed_true():
    """
    Tests that a certificate token can be initialized with a self-signed certificate and that the is_self_signed is True.
    """
    google_bytes = load_from_file("google/GTS Root R1.crt")
    certificate_token = CertificateToken(google_bytes)

    assert certificate_token.is_self_signed() is True


def test_certificate_token_is_self_signed_false():
    """
    Tests that a certificate token can be initialized with a non self-signed certificate and that the is_self_signed is False.
    """
    google_bytes = load_from_file("google/google.pem")
    certificate_token = CertificateToken(google_bytes)

    assert certificate_token.is_self_signed() is False


def test_certificate_token_x509_cert_available():
    """
    Tests that the x509_cert property returns an x509.Certificate object.
    """
    google_bytes = load_from_file("google/google.pem")

    cryptography_cert = x509.load_pem_x509_certificate(google_bytes)
    certificate_token = CertificateToken(google_bytes)

    assert certificate_token.x509_cert == cryptography_cert


def test_certificate_token_chain_empty():
    """
    Tests that the chain property returns an empty list when there is no chain.
    """
    google_bytes = load_from_file("google/google.pem")
    certificate_token = CertificateToken(google_bytes)

    assert certificate_token.chain == []


def test_certificate_token_chain_available():
    """
    Tests that the chain property returns a list of x509.Certificate objects when there is a chain.
    """
    google_bytes = load_from_file("google/google.p7c")

    certificate_token = CertificateToken(google_bytes)

    assert len(certificate_token.chain) == 2
