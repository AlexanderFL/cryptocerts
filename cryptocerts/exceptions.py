class InvalidCertificate(Exception):
    pass


class NotTrustedCertificate(Exception):
    pass


class CertificateAlreadyStored(Exception):
    pass


class CertificateNotYetValid(Exception):
    pass


class CertificateExpired(Exception):
    pass


class InvalidChain(Exception):
    pass
