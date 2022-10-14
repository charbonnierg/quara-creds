import typing as t
from dataclasses import dataclass

from quara.creds.nebula.interfaces import SigningOptions
from quara.creds.nebula.interfaces.certs import CACertificate, NodeCertificate
from quara.creds.nebula.interfaces.keys import PublicEncryptionKey, SigningKeyPair


@dataclass
class SigningRequest:
    authority: str
    options: SigningOptions

    def validate(self, ca: CACertificate) -> None:
        """Validate signing options accoring to CA certificate.

        Arguments:
            ca: CA certificate used to verify signing options.

        Returns:
            None
        """
        ca.verify_signing_options(self.options)

    def sign(
        self,
        ca: CACertificate,
        signing_key: SigningKeyPair,
        public_key: t.Union[PublicEncryptionKey, SigningKeyPair],
    ) -> NodeCertificate:
        """Sign a certificate according to signing request.

        Arguments:
            ca: CA certificate used to sign node certificate.
            signing_key: CA certificate signing keypair (nebula ed25519 private key).
            public_key: Node certificate public key (nebula x25519 public key).

        Returns:
            A NodeCertificate instance.
        """
        return ca.sign_certificate(
            signing_key=signing_key, public_key=public_key, options=self.options
        )
