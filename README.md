# QUARA Creds

## CLI usage

### Display help

Several subcommands are available. The `--help` option is available at different levels:

```bash
# General help
pync --help
# cert command group help
pync cert --help
# cert sign subcommand help
pync cert sign --help
```

### Initialize environment

- Initialize with default configuration

```bash
pync init
```

- Reset configuration

```bash
pync init --force
```

- Configure authorities from a JSON file (either a path or an URL):

```bash
pync init --authorities https://devquanebulajqtcetlst0.blob.core.windows.net/authorities/.well_known/authorities.json
```


### Manage keypairs

- Create a new keypair for current user:

```bash
pync key gen
```

- Create a new keypair for a different user:

```bash
pync key gen -n test
```

- List available keypairs

```bash
pync key list
```

- Display a public key

```bash
pync key show -n test
```

- Display a private key

```bash
pync key show -n test --private
```

### Manager certificate authorities

- List available authorities:

```bash
pync ca list
```

- Show authorities details:

```bash
pync ca show
```

- Show authorities certificates:

```bash
pync ca show --pem
```


## Nebula certs examples

#### Create a new CA and a sign a new certificate

```python
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
# Create a new keypair for the certificate
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
ca_crt.write_pem_file("ca.crt")
ca_keypair.write_private_key("ca.key")
new_crt.write_pem_file("node.crt")
enc_keypair.write_private_key("node.key")
enc_keypair.write_public_key("node.pub")
# Verify that the certificate is valid
verify_certificate(ca_crt=ca_crt, crt=new_crt)
```

This example generates 5 files:
- `ca.crt`: The CA certificate created during the first step.
- `ca.key`: The private key of the CA. The public key is also present within this file.
- `node.crt`: The certificate created during the second step.
- `node.key`: The private key associated with the certificate. Unlike CA private keys, the public key is not present within the file.
- `node.pub`: The public key associated with the certificate. The public key is also embedded within the certificate.

#### Load an existing CA and sign a new certificate

```python
from quara.creds.nebula import (
    Certificate,
    EncryptionKeyPair,
    SigningKeyPair,
    SigningOptions,
    sign_cert,
    verify_certificate,
)

# Load CA certificate
ca_crt = Certificate.from_file("ca.crt")
# Load CA keypair
ca_keypair = SigningKeyPair.from_file("ca.key")
# Create a new keypair for the certificate
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
new_crt.write_pem_file("node.crt")
enc_keypair.write_private_key("node.key")
enc_keypair.write_public_key("node.pub")
# Verify that the certificate is valid
verify_certificate(ca_crt=ca_crt, crt=new_crt)
```

In this case, only 3 files are created, as the CA certificate and the CA key already existed before.

#### Load an existing CA, an existing public key, and sign a new certificate

```python
from quara.creds.nebula import (
    Certificate,
    PublicEncryptionKey,
    SigningKeyPair,
    SigningOptions,
    sign_cert,
    verify_certificate,
)

# Load CA certificate
ca_crt = Certificate.from_file("ca.crt")
# Load CA keypair
ca_keypair = SigningKeyPair.from_file("ca.key")
# Load public key from file
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
verify_certificate(ca_crt=ca_crt, crt=new_crt)
```

In this case, only the certificate file is written to disk, as all other information was known before issuing the certificate.
