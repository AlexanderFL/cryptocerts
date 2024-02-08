from dataclasses import dataclass
from datetime import datetime

from cryptocerts import CertificateToken
from cryptocerts.validators.enums import ValidationStatus, ValidatorErrors


@dataclass
class CertificateValidationResult:
    certificate_token: CertificateToken
    validation_status: ValidationStatus
    validation_errors: list[ValidatorErrors]


@dataclass
class ValidationResult:
    validation_conclusion: ValidationStatus
    validation_time: datetime
    valid_to_trusted_root: bool
    certificate_validation_result: list[CertificateValidationResult]
