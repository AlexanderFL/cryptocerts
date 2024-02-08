from __future__ import annotations

from datetime import datetime

from cryptography.exceptions import InvalidSignature

from cryptocerts.exceptions import CertificateExpired, CertificateNotYetValid
from cryptocerts.paths.builder import CertificatePathBuilder
from cryptocerts.stores import CertificatesStore
from cryptocerts.stores.exceptions import CertificateNotFoundError
from cryptocerts.token import CertificateToken
from cryptocerts.utils import ensure_aware_datetime
from cryptocerts.validators.enums import ValidationStatus, ValidatorErrors

from .objects import CertificateValidationResult, ValidationResult


class CertificateValidator:
    """
    An object that can verify certificates using a trusted and intermediary store.
    """

    def __init__(
        self,
        certificates_store: CertificatesStore | None = None,
        certificate_path_builder: CertificatePathBuilder | None = None,
    ):
        self.certificates_store = certificates_store or CertificatesStore(None, None)
        self.certificate_path_builder = certificate_path_builder or CertificatePathBuilder(self.certificates_store)

    def validate_certificate(self, certificate: CertificateToken, validation_time: datetime | None = None) -> ValidationResult:
        """
        Verifies a certificate using the trusted and intermediary store.

        Can optionally take a `validation_time` to validate the certificate at a specific time.
        """

        validation_time = ensure_aware_datetime(validation_time)
        path = self.certificate_path_builder.build(certificate)

        # Immediately check if the last certificate (root) is in the trusted store
        try:
            trusted_certificate = self.certificates_store.get_certificate_by_name_from_trusted(path[len(path) - 1].subject)
        except CertificateNotFoundError:
            trusted_certificate = None

        validation_result = ValidationResult(
            certificate_validation_result=[],
            validation_time=validation_time,
            valid_to_trusted_root=trusted_certificate is not None,
            validation_conclusion=ValidationStatus.UNKNOWN,
        )

        for i, certificate_token in enumerate(path):
            errors: list[ValidatorErrors] = []

            # Check if certificate is valid at the given time
            try:
                certificate_token.check_validitiy_period(validation_time)
            except CertificateNotYetValid as e:
                errors.append(ValidatorErrors.NOT_YET_VALID)
            except CertificateExpired as e:
                errors.append(ValidatorErrors.EXPIRED)

            # Check if the certificate is in the trusted store
            try:
                certificate_token.verify_directly_issued_by(path[i + 1].x509_cert)
            except InvalidSignature:
                errors.append(ValidatorErrors.SIGNATURE_INVALID)
            except IndexError:
                pass

            # Check if the certificate is traceable to a trusted root
            if trusted_certificate is None:
                errors.append(ValidatorErrors.NO_TRUSTED_ROOT)

            # TODO: Check for revocation

            result = CertificateValidationResult(
                certificate_token=certificate_token,
                validation_errors=errors,
                validation_status=(ValidationStatus.INVALID if errors else ValidationStatus.VALID),
            )

            validation_result.certificate_validation_result.append(result)

        # If any certificate in the chain is invalid, the whole chain is invalid
        if any(
            certificate_result.validation_status == ValidationStatus.INVALID
            for certificate_result in validation_result.certificate_validation_result
        ):
            validation_result.validation_conclusion = ValidationStatus.INVALID
        else:
            validation_result.validation_conclusion = ValidationStatus.VALID

        return validation_result
