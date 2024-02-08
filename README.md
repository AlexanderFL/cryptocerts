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
from cryptocerts import CertificateToken

# From a file
certificate = CertificateToken.load_from_file("filepath/mycert.crt")

# From bytes
certificate = CertificateToken(b"<certificate bytes>")
```

### Validate a certificate with a custom certificate store

Validate that a certificate is valid up to a custom trusted root

```python
from cryptocerts import (
    CertificateToken,
    CertificateValidator,
    CertificatesStore
)

my_trusted_roots : list[CertificateToken] = [ ... ]
my_intermediate_certificates : list[CertificateTokens] = [ ... ]
certificates_store = CertificatesStore(my_trusted_roots, my_intermediate_certificates)
certificate_validator = CertificateValidator(certificates_store)

# `result` contains validation info about the certificate, 
# f.x. a valid certificate
result = certificate_validator.verify_certificate(certificate)
result.validation_conclusion # ValidationStatus.VALID
result.valid_to_trusted_root # True
result.certificate_validation_result[0].certificate_token # <certificate>
result.certificate_validation_result[0].validation_errors # []

# and an invalid certificate
result = certificate_validator.verify_certificate(invalid_certificate)
result.validation_conclusion # ValidationStatus.INVALID
result.valid_to_trusted_root # True
result.certificate_validation_result[0].certificate_token # <invalid_certificate>
result.certificate_validation_result[0].validation_errors # [ValidatorErrors.EXPIRED]
```