Library that wraps around the `cryptography` library, aiming to simplify the loading and validation of certificates. Providing a more streamlined interface instead of delving into the intricacies of certificate operations.

*Note* that this project is still not meant for production-use scenarios, use it at your own risk.

## Installation

This library is available on the python package index, you can install it like via `pip`

```bash
pip install cryptocerts
```

## Contributing

Community contributes are welcome. Please use the Github issue tracker for any feature, requests or bugs you might encounter.

## Usage

### Loading a certificate

Easier loading a certificate without having to know which format it is

```python
from cryptocerts.certificates import CertificateToken

# From a file
certificate = CertificateToken.load_from_file("filepath/mycert.crt")

# From bytes
certificate = CertificateToken(b"<certificate bytes>")
```

### Validate a certificate with a custom certificate store

Validate that a certificate is valid up to a custom trusted root

```python
from cryptocerts.certificates import (
    CertificateToken,
    CertificateVerifier,
    TrustedCertificateStore,
    IntermediaryCertificateStore
)

my_trusted_roots : list[CertificateToken] = [ ... ]
my_intermediate_certificates : list[CertificateTokens] = [ ... ]
certificate_verifier = CertificateVerifier(my_trusted_roots, my_intermediate_certificates)

certificate = CertificateToken(b"<certificate bytes>")
result = certificate_verifier.verify_certificate(my_certificate)
# `result` contains validation info about the certificate
result.valid_to_trusted_root
result.signature_intact
result.not_yet_valid
result.is_expired
```