from cryptography.x509 import Name

from cryptocerts.stores import IntermediaryCertificateStore, TrustedCertificateStore
from cryptocerts.stores.exceptions import (
    CertificateAlreadyStored,
    CertificateNotFoundError,
)
from cryptocerts.token import CertificateToken


class CertificatesStore:
    def __init__(
        self,
        intermediate_store: IntermediaryCertificateStore | list[CertificateToken] | None,
        trusted_store: TrustedCertificateStore | list[CertificateToken] | None,
    ):
        if isinstance(intermediate_store, IntermediaryCertificateStore):
            self.intermediate_store = intermediate_store
        else:
            self.intermediate_store = IntermediaryCertificateStore(intermediate_store)

        if isinstance(trusted_store, TrustedCertificateStore):
            self.trusted_store = trusted_store
        else:
            self.trusted_store = TrustedCertificateStore(trusted_store)

        for intermediate_certificate in self.intermediate_store:
            if intermediate_certificate in self.trusted_store:
                raise CertificateAlreadyStored(
                    f"Intermediate store contains a certificate {intermediate_certificate.subject} that is already stored in the trusted store, this is not allowed."
                )

    def get_certificate_by_name(self, name: Name) -> CertificateToken:
        """
        Get a certificate by its name.

        - Raises `CertificateNotFoundError` if the certificate is not found.
        """

        try:
            return self.intermediate_store.get_certificate_by_name(name)
        except CertificateNotFoundError:
            pass

        try:
            return self.trusted_store.get_certificate_by_name(name)
        except CertificateNotFoundError:
            pass

        raise CertificateNotFoundError(f"Certificate with subject {name} not found in either trusted or intermediate store")

    def get_certificate_by_name_from_trusted(self, name: Name) -> CertificateToken:
        """
        Get a certificate by its name from the trusted store.

        - Raises `CertificateNotFoundError` if the certificate is not found.
        """

        return self.trusted_store.get_certificate_by_name(name)

    def get_certificate_by_name_from_intermediate(self, name: Name) -> CertificateToken:
        """
        Get a certificate by its name from the intermediate store.

        - Raises `CertificateNotFoundError` if the certificate is not found.
        """

        return self.intermediate_store.get_certificate_by_name(name)
