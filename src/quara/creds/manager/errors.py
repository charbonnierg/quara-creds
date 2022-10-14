class StorageError(Exception):
    pass


class NotFoundError(StorageError):
    pass


class AlreadyExistsError(StorageError):
    pass


class AuthorityNotFoundError(NotFoundError):
    pass


class PublicKeyNotFoundError(NotFoundError):
    pass


class KeyPairNotFoundError(NotFoundError):
    pass


class CertificateNotFoundError(NotFoundError):
    pass


class SigningRequestNotFoundError(NotFoundError):
    pass


class KeyPairExistsError(AlreadyExistsError):
    pass


class PublicKeyExistsError(AlreadyExistsError):
    pass


class CertificateExistsError(NotFoundError):
    pass


class SigningRequestExistsError(AlreadyExistsError):
    pass
