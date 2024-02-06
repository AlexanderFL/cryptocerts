from __future__ import annotations

import pytest
from cryptocerts.stores import TrustedCertificateStore
from cryptocerts import CertificateToken
from cryptocerts.exceptions import InvalidCertificate


def test_trusted_store_add_certificate(root_certificate_token: CertificateToken):
    """
    Tests that a certificate can be added to the trusted store.
    """
    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)

    assert root_certificate_token in trusted_store


def test_trusted_store_remove_certificate(root_certificate_token: CertificateToken):
    """
    Tests that a certificate can be removed from the trusted store.
    """
    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)
    trusted_store.remove_certificate(root_certificate_token)
    assert root_certificate_token not in trusted_store


def test_trusted_store_remove_certificate_returns_certificate(
    root_certificate_token: CertificateToken,
):
    """
    Tests that a certificate can be removed from the trusted store and that it is returned.
    """
    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)
    certificate = trusted_store.remove_certificate(root_certificate_token)
    assert certificate == root_certificate_token


def test_trusted_store_remove_certificate_not_in_store(
    root_certificate_token: CertificateToken,
):
    """
    Tests that None is returned when trying to remove a certificate that is not in the store.
    """
    trusted_store = TrustedCertificateStore()
    certificate = trusted_store.remove_certificate(root_certificate_token)
    assert certificate is None


def test_trusted_store_iter(root_certificate_token: CertificateToken):
    """
    Tests that the trusted store can be iterated over.
    """
    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)
    for cert in trusted_store:
        assert isinstance(cert, CertificateToken)


def test_trusted_store_len(root_certificate_token: CertificateToken):
    """
    Tests that the length of the trusted store is correct.
    """
    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)
    assert len(trusted_store) == 1


def test_trusted_store_add_certificate_trusted(
    root_certificate_token: CertificateToken,
):
    """
    Tests that a certificate can be added to the trusted store as trusted.
    """
    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)
    assert root_certificate_token.is_trusted is True


def test_trusted_store_certificate_property(root_certificate_token: CertificateToken):
    """
    Tests that the certificates property returns the correct value.
    """
    trusted_store = TrustedCertificateStore()
    trusted_store.add_certificate(root_certificate_token)
    assert trusted_store.certificates == [root_certificate_token]


def test_trusted_store_init_empty():
    """
    Tests that the trusted store can be initialized empty.
    """
    trusted_store = TrustedCertificateStore()
    assert trusted_store.certificates == []


def test_trusted_store_init_list(root_certificate_token: CertificateToken):
    """
    Tests that the trusted store can be initialized with a list of certificates.
    """
    trusted_store = TrustedCertificateStore([root_certificate_token])
    assert trusted_store.certificates == [root_certificate_token]


def test_trusted_store_init_raises_invalid_certificate():
    """
    Tests that the trusted store will raise an InvalidCertificate exception if the init list contains an invalid certificate.
    """

    def the_test():
        trusted_store = TrustedCertificateStore(["abc"])

    pytest.raises(InvalidCertificate, the_test)
