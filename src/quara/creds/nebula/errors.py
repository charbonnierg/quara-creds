class InvalidCertificateError(ValueError):
    def __init__(self, msg: str, *args: object) -> None:
        super().__init__(msg, *args)
        self.msg = msg


class InvalidSigningOptionError(ValueError):
    def __init__(self, msg: str, *args: object) -> None:
        super().__init__(msg, *args)
        self.msg = msg
