import typing as t
from dataclasses import asdict, dataclass
from json import dumps, loads
from pathlib import Path


@dataclass
class NebulaCertManagerSettings:
    default_user: t.Optional[str] = None
    storage: t.Optional[t.Mapping[str, t.Mapping[str, t.Any]]] = None

    @classmethod
    def from_json(cls, filepath: t.Union[str, Path]) -> "NebulaCertManagerSettings":
        """Parse settings from a JSON file."""
        content = Path(filepath).read_bytes()
        data = loads(content)
        return cls(
            default_user=data.get("default_user", None),
            storage=data.get("storage", None),
        )


class SettingsProvider:
    def __init__(self, filepath: t.Union[str, Path]) -> None:
        self.filepath = Path(filepath).expanduser()

    def get_settings(self) -> NebulaCertManagerSettings:
        return NebulaCertManagerSettings.from_json(self.filepath)

    def write_settings(self, settings: NebulaCertManagerSettings) -> None:
        self.filepath.write_bytes(dumps(asdict(settings)).encode("utf-8"))
