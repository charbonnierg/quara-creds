import typing as t

from quara.creds.manager.interfaces.keystore import CAKeyStore


def create_store(uri: str, **kwargs: t.Any) -> CAKeyStore:
    """Create a new keystore instance"""
    if "://" not in uri:
        from quara.creds.manager.adapters.keystores.file_keystore import FileCAKeyStore

        return FileCAKeyStore(root=uri)
    prefix, name = uri.split("://")
    if prefix == "azkv":
        from quara.creds.manager.adapters.keystores.azkv_keystore import AzureCAKeyStore

        return AzureCAKeyStore(name, **kwargs)
    elif prefix == "file://":
        from quara.creds.manager.adapters.keystores.file_keystore import FileCAKeyStore

        return FileCAKeyStore(name)
    else:
        raise ValueError(f"Invalid keystore backend: {prefix}")
