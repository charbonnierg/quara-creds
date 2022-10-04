from quara.creds.nebula import Certificate, SigningKeyPair, SigningOptions, sign_cert
from quara.creds.nebula.cert import PublicEncryptionKey

# Load CA certificate
ca_crt = Certificate.from_file("ca.crt")
# Load keypair
ca_keypair = SigningKeyPair.from_file("ca.key")
# Load certificate public key
pub_key = PublicEncryptionKey.from_file("node.pub")
# Sign a new certificate
new_crt = sign_cert(
    ca_key=ca_keypair,
    ca_crt=ca_crt,
    public_key=pub_key,
    options=SigningOptions(
        Name="test",
        Ip="10.100.100.10/24",
    ),
)
# Write files to disk
new_crt.write_pem_file("node.crt")
# Verify that the certificate is valid
new_crt.verify(ca_crt)
