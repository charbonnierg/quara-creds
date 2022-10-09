from quara.creds.nebula import (
    EncryptionKeyPair,
    SigningCAOptions,
    SigningOptions,
    sign_ca,
    sign_cert,
    verify_certificate,
)

# Create a new CA
ca_keypair, ca_crt = sign_ca(options=SigningCAOptions(Name="test"))

# Create a new keypair
enc_keypair = EncryptionKeyPair()

# Sign a new certificate
new_crt = sign_cert(
    ca_key=ca_keypair,
    ca_crt=ca_crt,
    public_key=enc_keypair,
    options=SigningOptions(
        Name="test",
        Ip="10.100.100.10/24",
    ),
)

# Write files to disk
ca_crt.write_pem_file("test/ca.crt")
ca_keypair.write_private_key("test/ca.key")
new_crt.write_pem_file("test/node.crt")
enc_keypair.write_private_key("test/node.key")
enc_keypair.write_public_key("test/node.pub")

# Verify that the certificate is valid
verify_certificate(ca_crt=ca_crt, crt=new_crt)
