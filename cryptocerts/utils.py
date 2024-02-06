from cryptography import x509
from cryptocerts.exceptions import InvalidChain


def try_build_certificate_chain(certificates: list[x509.Certificate]):
    """
    Attempts to build a certificate chain from a list of certificates, must contain a root certificate.

    :param certificates: The certificates to build the chain from.
    :return: The certificate chain in order from the leaf to the root.
    """
    if len(certificates) <= 1:
        return certificates

    ordered_chain: list[x509.Certificate] = []

    # Find the root certificate
    root_certificate = None
    for cert in certificates:
        try:
            cert.verify_directly_issued_by(cert)
            root_certificate = cert
            break
        except Exception:
            pass

    if root_certificate is None:
        raise InvalidChain(f"Could not find the root certificate for {certificates}")

    # Build the chain from the root
    ordered_chain.append(root_certificate)
    for _ in range(0, len(certificates)):
        for cert in certificates:
            if cert in ordered_chain:
                continue
            try:
                last_cert = ordered_chain[len(ordered_chain) - 1]
                cert.verify_directly_issued_by(last_cert)
                ordered_chain.append(cert)
                break
            except Exception:
                pass

    if len(ordered_chain) != len(certificates):
        raise InvalidChain(f"Could not order the certificate chain for {certificates}")

    ordered_chain.reverse()
    return ordered_chain
