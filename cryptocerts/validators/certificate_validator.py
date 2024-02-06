from __future__ import annotations
from dataclasses import dataclass

from cryptocerts.stores import TrustedCertificateStore, IntermediaryCertificateStore
from cryptocerts.exceptions import (
    CertificateAlreadyStored,
    InvalidCertificate,
    InvalidChain,
    CertificateExpired,
    CertificateNotYetValid,
)
from cryptocerts.token import CertificateToken


class CertificateValidator:
    """
    An object that can verify certificates using a trusted and intermediary store.
    """

    def __init__(
        self,
        trusted_store: TrustedCertificateStore | None = None,
        intermediary_store: IntermediaryCertificateStore | None = None,
    ):
        self._trusted_store = (
            trusted_store if trusted_store is not None else TrustedCertificateStore()
        )
        self._intermediary_store = (
            intermediary_store
            if intermediary_store is not None
            else IntermediaryCertificateStore()
        )

        self.set_trusted_store(self._trusted_store)
        self.set_intermediary_store(self._intermediary_store)

    def set_trusted_store(self, store: TrustedCertificateStore) -> None:
        """
        Sets the trusted store of the verifier.
        """
        self._trusted_store = store

    def set_intermediary_store(self, store: IntermediaryCertificateStore) -> None:
        """
        Sets the intermediary store of the verifier.
        """
        for cert in store.certificates:
            if cert in self._trusted_store:
                raise CertificateAlreadyStored(
                    "Certificate is already in the trusted store"
                )

            is_valid = False
            for trusted_certs in self._trusted_store:
                try:
                    cert.verify_directly_issued_by(trusted_certs._x509_cert)
                    is_valid = True
                except:
                    pass

            if not is_valid:
                raise InvalidChain(
                    f"CertificateToken {cert} can't be built to a trusted certificate. (Did you forget to add the issuer to the trusted store?)"
                )
        self._intermediary_store = store

    def validate_certificate(self, certificate: CertificateToken) -> ValidationResult:
        """
        Verifies a certificate using the trusted and intermediary store.

        TODO: Refactor this method to be more readable.
        """

        result = ValidationResult(False, False, False, False)

        # Verify the validity period
        try:
            certificate.check_validitiy_period()
        except CertificateNotYetValid:
            result.not_yet_valid = True
        except CertificateExpired:
            result.is_expired = True

        # Self signed certificate are easy to verify
        if certificate.is_self_signed():
            result.signature_intact = True
            if certificate in self._trusted_store:
                result.valid_to_trusted_root = True
            return result

        # Verify the certificate chain if there is one
        if certificate.chain != []:
            selected_cert = certificate.x509_cert
            for cert_in_chain in certificate.chain:
                try:
                    selected_cert.verify_directly_issued_by(cert_in_chain)
                    selected_cert = cert_in_chain
                except Exception:
                    raise InvalidCertificate(
                        f"Certificate chain is invalid at {selected_cert}"
                    )
            result.signature_intact = True

            # Verify the certificate against the trusted store
            if certificate.chain[len(certificate.chain) - 1] in self._trusted_store:
                result.valid_to_trusted_root = True
            return result

        # No certificate chain, so we need to build the chain ourselves using the stores
        intermediate_chain_complete = False
        valid_to_trusted = False
        certificate_chain: list[CertificateToken] = []
        last_chain_length = 0
        selected_x509cert = certificate.x509_cert

        while not intermediate_chain_complete:

            for x509_cert in self._intermediary_store:
                try:
                    selected_x509cert.verify_directly_issued_by(x509_cert.x509_cert)
                    certificate_chain.append(x509_cert)
                    selected_x509cert = x509_cert.x509_cert
                    result.signature_intact = True
                except Exception:
                    pass

            if last_chain_length == len(certificate_chain):
                intermediate_chain_complete = True
            last_chain_length += 1

        for x509_cert in self._trusted_store:
            try:
                selected_x509cert.verify_directly_issued_by(x509_cert.x509_cert)
                certificate_chain.append(x509_cert)
                valid_to_trusted = True
                result.signature_intact = True
            except Exception:
                pass

        if valid_to_trusted:
            result.valid_to_trusted_root = True

        return result


@dataclass
class ValidationResult:
    valid_to_trusted_root: bool
    not_yet_valid: bool
    is_expired: bool
    signature_intact: bool
