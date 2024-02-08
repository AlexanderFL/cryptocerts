from enum import Enum


class ValidatorErrors(Enum):
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SIGNATURE_INVALID = "signature_invalid"
    NO_TRUSTED_ROOT = "no_trusted_root"


class ValidationStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
