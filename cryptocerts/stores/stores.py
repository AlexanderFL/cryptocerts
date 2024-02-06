from cryptocerts.token import CertificateToken
from cryptocerts.exceptions import InvalidCertificate


class CertificateStore:
    """
    A base class for certificate stores.
    """

    def __init__(self, certificates: list[CertificateToken] | None = None):
        self._certificates: list[CertificateToken] = []

        for certificate in certificates or []:
            self.add_certificate(certificate)

    @property
    def certificates(self) -> list[CertificateToken]:
        return self._certificates

    def add_certificate(self, certificate: CertificateToken) -> None:
        """
        Adds a certificate to the trusted store.
        """
        if not isinstance(certificate, CertificateToken):
            raise InvalidCertificate(
                f"Certificate {certificate} is not a CertificateToken."
            )
        self._certificates.append(certificate)

    def remove_certificate(
        self, certificate: CertificateToken
    ) -> CertificateToken | None:
        """
        Removes a certificate from the trusted store and returns it.
        """
        try:
            self._certificates.remove(certificate)
        except ValueError:
            return None
        return certificate

    def __iter__(self):
        return iter(self._certificates)

    def __len__(self):
        return len(self._certificates)


class TrustedCertificateStore(CertificateStore):
    """
    A store of trusted certificates.
    """

    def add_certificate(self, certificate: CertificateToken) -> None:
        """
        Adds a certificate to the trusted store.
        """
        super().add_certificate(certificate)
        certificate.is_trusted = True


class IntermediaryCertificateStore(CertificateStore):
    """
    A store of intermediary certificates.
    """

    def add_certificate(self, certificate: CertificateToken) -> None:
        """
        Adds a certificate to the intermediary store.
        """
        super().add_certificate(certificate)
        certificate.is_intermediate = True
