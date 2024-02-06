from __future__ import annotations
from cryptography import x509
from cryptography.x509.base import Version
from cryptography.x509.extensions import Extensions
from cryptography.hazmat.primitives import serialization
from cryptography.x509.name import Name
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)
from datetime import datetime, timezone
from cryptocerts.exceptions import (
    InvalidCertificate,
    CertificateNotYetValid,
    CertificateExpired,
    InvalidChain,
)
from cryptocerts.certificates.utils import try_build_certificate_chain


class CertificateToken(x509.Certificate):
    """
    Represents an X.509 certificate.
    """

    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise InvalidCertificate("Data must be bytes")

        data_loaded = CertificateToken.load_x509_from_bytes(data)

        if isinstance(data_loaded, list):
            built_chain = try_build_certificate_chain(data_loaded)
            first_cert = built_chain[0]
            chain = built_chain[1:]
        else:
            first_cert = data_loaded
            chain = []

        self._x509_cert: x509.Certificate = first_cert
        self._chain: list[x509.Certificate] = chain

        self.is_intermediate: bool = False
        self.is_trusted: bool = False

    @property
    def x509_cert(self) -> x509.Certificate:
        """
        The `x509.Certificate` object from `cryptography`
        """
        return self._x509_cert

    @property
    def chain(self) -> list[x509.Certificate]:
        """
        The certificate chain of the certificate in order from the issuer to the root.
        """
        return self._chain

    @staticmethod
    def load_from_file(path: str) -> CertificateToken:
        """
        Tries to load the certificate from a file.
        """
        with open(path, "rb") as f:
            return CertificateToken(f.read())

    @staticmethod
    def load_x509_from_bytes(data: bytes) -> x509.Certificate | list[x509.Certificate]:
        """
        Tries to load the certificate from the bytes provided with different methods.
        """
        # Try to load multiple x509 certificates
        try:
            return x509.load_pem_x509_certificates(data)
        except Exception:
            pass

        # Try to load as a PKCS#7 certificate chain
        try:
            return pkcs7.load_pem_pkcs7_certificates(data)
        except Exception:
            pass

        try:
            return pkcs7.load_der_pkcs7_certificates(data)
        except Exception:
            pass

        # Try to load as a single x509 certificate
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:
            pass

        try:
            return x509.load_der_x509_certificate(data)
        except Exception:
            pass

        raise InvalidCertificate("Could not load certificate from bytes")

    def is_self_signed(self) -> bool:
        """
        Returns whether the certificate is self-signed or not.
        """
        try:
            self._x509_cert.verify_directly_issued_by(self._x509_cert)
            return True
        except Exception:
            return False

    def check_validitiy_period(self) -> None:
        """
        Checks the validity period of the certificate.

        Raises:
            `CertificateExpired`: The certificate has expired.
            `CertificateNotYetValid`: The certificate is not yet valid.
        """

        if self.not_valid_before_utc > datetime.now(timezone.utc):
            raise CertificateNotYetValid(f"Certificate {self} is not yet valid")

        if self.not_valid_after_utc < datetime.now(timezone.utc):
            raise CertificateExpired(f"Certificate {self} has expired")

    def __str__(self) -> str:
        return self.x509_cert.__str__()

    """
    Methods overriden from `cryptography.x509.Certificate`
    """

    def fingerprint(self, algorithm: hashes.HashAlgorithm) -> bytes:
        return self._x509_cert.fingerprint(algorithm)

    @property
    def serial_number(self) -> int:
        return self._x509_cert.serial_number

    @property
    def version(self) -> Version:
        return self._x509_cert.version

    def public_key(self) -> CertificatePublicKeyTypes:
        return self._x509_cert.public_key()

    @property
    def not_valid_before(self) -> datetime:
        return self._x509_cert.not_valid_before

    @property
    def not_valid_before_utc(self) -> datetime:
        return self._x509_cert.not_valid_before_utc

    @property
    def not_valid_after(self) -> datetime:
        return self._x509_cert.not_valid_after

    @property
    def not_valid_after_utc(self) -> datetime:
        return self._x509_cert.not_valid_after_utc

    @property
    def issuer(self) -> Name:
        return self._x509_cert.issuer

    @property
    def subject(self) -> Name:
        return self._x509_cert.subject

    @property
    def signature_hash_algorithm(
        self,
    ) -> hashes.HashAlgorithm | None:
        return self._x509_cert.signature_hash_algorithm

    @property
    def signature_algorithm_oid(self) -> ObjectIdentifier:
        return self._x509_cert.signature_algorithm_oid

    @property
    def signature_algorithm_parameters(
        self,
    ) -> None | padding.PSS | padding.PKCS1v15 | ec.ECDSA:
        return self._x509_cert.signature_algorithm_parameters

    @property
    def extensions(self) -> Extensions:
        return self._x509_cert.extensions

    @property
    def signature(self) -> bytes:
        return self._x509_cert.signature

    @property
    def tbs_certificate_bytes(self) -> bytes:
        return self._x509_cert.tbs_certificate_bytes

    @property
    def tbs_precertificate_bytes(self) -> bytes:
        return self._x509_cert.tbs_precertificate_bytes

    def __eq__(self, other: object) -> bool:
        return self._x509_cert.__eq__(other)

    def __hash__(self) -> int:
        return self._x509_cert.__hash__()

    def public_bytes(self, encoding: serialization.Encoding) -> bytes:
        return self._x509_cert.public_bytes(encoding)

    def verify_directly_issued_by(self, issuer: x509.Certificate) -> None:
        return self._x509_cert.verify_directly_issued_by(issuer)
