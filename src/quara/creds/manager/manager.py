import os
import typing as t
from pathlib import Path

from quara.creds.manager.adapters.storages.file_storage import FileStorageBackend

from .adapters.storages import create_store
from .settings import SettingsProvider
from .user import UsernameProvider


class NebulaCertManager:

    DEFAULT_USER_ENV = "PYNC_NEBULA_USER"

    def __init__(
        self,
        settings_provider: SettingsProvider,
        username_provider: UsernameProvider,
    ) -> None:
        """A NebulaCertManager is initialized using a root repository"""
        self.username_provider = username_provider
        self.settings_provider = settings_provider
        self.reload_settings()

    @classmethod
    def from_root(cls, root: t.Union[str, Path, None] = None) -> "NebulaCertManager":
        """Create a NebulaCertManager instance from a root directory path"""
        root = root or "~/.nebula"
        return cls.from_config_file(Path(root) / "config.json")

    @classmethod
    def from_config_file(cls, filepath: t.Union[str, Path]) -> "NebulaCertManager":
        config_provider = SettingsProvider(filepath)
        return cls(config_provider, username_provider=UsernameProvider())

    def reload_settings(self) -> None:
        """Reload configuration."""
        self.settings = self.settings_provider.get_settings()
        self.default_user = (
            os.environ.get(self.DEFAULT_USER_ENV, self.settings.default_user)
            or self.username_provider.get_user()
        )
        self.storage = create_store(self.settings.storage)
        self.authorities = self.storage.get_authorities()

    def describe_settings(self) -> t.Dict[str, t.Any]:
        """Describe settings as key/value pairs"""
        items = {
            "Configuration file": self.settings_provider.filepath.as_posix(),
        }
        if isinstance(self.storage, FileStorageBackend):
            items["Authorities file"] = self.storage.settings.authorities.as_posix()
            items["CA store"] = self.storage.settings.signing_certificates.as_posix()
            items["Cert store"] = self.storage.settings.certificates.as_posix()
            items["Key store"] = self.storage.settings.keys.as_posix()
        return items
