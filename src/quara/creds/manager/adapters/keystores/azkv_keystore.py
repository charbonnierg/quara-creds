import typing as t

from quara.creds.manager.interfaces.keystore import CAKeyStore
from quara.creds.nebula import SigningKeyPair


class AzureCAKeyStore(CAKeyStore):
    """An Azure Keyvault store"""

    def __init__(self, keyvault: str, creds: t.Any = None) -> None:
        self.keyvault = keyvault
        self.creds = creds

    def get_ca_key(self, name: str) -> SigningKeyPair:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        secrets_uri = f"https://{self.keyvault}.vault.azure.net"
        secrets_creds = self.creds or DefaultAzureCredential(
            exclude_interactive_browser_credential=False,
            exclude_shared_token_cache_credential=True,
            exclude_visual_studio_code_credential=True,
        )
        client = SecretClient(vault_url=secrets_uri, credential=secrets_creds)
        with client:
            ca_key = client.get_secret(f"{name}-key").value
        if ca_key is None:
            raise ValueError("CA key is empty")
        return SigningKeyPair.from_bytes(ca_key.encode("utf-8"))
