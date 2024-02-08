from collections import OrderedDict
from copy import deepcopy
from typing import cast

import requests
from cryptography import x509
from cryptography.x509.extensions import AccessDescription, ExtensionNotFound

from cryptocerts.stores.certificates_store import CertificatesStore
from cryptocerts.token import CertificateToken


class CertificatePathBuilder:
    """
    A class that can build a certificate path from a given certificate and the store to search in.
    """

    def __init__(self, certificate_store: CertificatesStore):
        self.certificate_store = certificate_store

    def build(self, certificate: CertificateToken):
        """
        Builds a certificate path from the given certificate. No validation is performed.

        Returns a list of `CertificateToken` objects ordered from the given certificate to the root.

        - Raises `CertificateNotFoundError` if a certificate to the path is not found.
        """

        # Modification to the certificate store might be needed temporarily, so to avoid
        # potential threading issues we create a deep copy of the store.
        deepcopy_certificate_store = deepcopy(self.certificate_store)

        certificate_discovery = self._discover_all_certificates(certificate)
        for discovered_certificate in certificate_discovery:
            deepcopy_certificate_store.intermediate_store.certificates.insert(0, discovered_certificate)

        current_certificate = certificate
        path = [certificate]
        while current_certificate.issuer != current_certificate.subject:
            # `get_certificate_by_name` throws CertificateNotFoundError if the certificate is not found
            current_certificate = deepcopy_certificate_store.get_certificate_by_name(current_certificate.issuer)
            if current_certificate not in path:
                path.append(current_certificate)

        return path

    def _discover_all_certificates(self, certificate: CertificateToken) -> list[CertificateToken]:
        """
        Discovers all certificates in the path of the given certificate.

        Returns a list of `CertificateToken` objects ordered from the given certificate to the root.

        - Raises `CertificateNotFoundError` if a certificate to the path is not found.
        """

        discovered_certificates: list[CertificateToken] = []

        # If the certificate contains a chain, we add it to the discovered certificates
        # TODO: Should we assume the chain is complete here?
        for certificate_chain in certificate.chain:
            discovered_certificates.append(CertificateToken(certificate_chain))

        # Get the all of the certificates from the AIA extension
        keep_searching = True
        while keep_searching is True:
            try:
                issuer_online_path = self._get_AIA_CA_issuer_location(certificate)
            except ExtensionNotFound:
                keep_searching = False
                break

            aia_certificate = self._fetch_online_certificate(issuer_online_path)
            if len(aia_certificate.chain) > 0:
                discovered_certificates.extend([CertificateToken(aia_certificate) for aia_certificate in aia_certificate.chain])
                keep_searching = False
            discovered_certificates.append(aia_certificate)
            certificate = aia_certificate

        discovered_certificates = list(OrderedDict.fromkeys(discovered_certificates))  # Remove duplicates
        return discovered_certificates

    def _get_AIA_CA_issuer_location(self, certificate: CertificateToken) -> str:
        """
        Returns the CA issuers from the AIA extension of the given certificate token.

        - Raises `ExtensionNotFound` if the AIA extension is not found.
        """
        aia_extension = certificate.x509_cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        aia_list: list[AccessDescription] = cast(list[AccessDescription], aia_extension.value)

        for aia in aia_list:
            if aia.access_method == x509.OID_CA_ISSUERS:
                return aia.access_location.value
        raise ExtensionNotFound(
            "CA Issuers extension not found in AIA extension", x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )

    def _fetch_online_certificate(self, location: str) -> CertificateToken:
        """
        Fetches a certificate from the given location.
        """

        request = requests.get(url=location)
        request.raise_for_status()
        certificate_token = CertificateToken(request.content)
        return certificate_token
