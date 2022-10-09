import typing as t

from quara.creds.manager.interfaces.storage import Store


def create_store(options: t.Mapping[str, t.Mapping[str, t.Any]]) -> Store:
    if not options:
        from quara.creds.manager.adapters.storages.file_storage import (
            FileStorageBackend,
            FileStorageOptions,
        )

        return FileStorageBackend(FileStorageOptions())
    else:
        if len(options) != 1:
            raise ValueError("Invalid file storage options")
        if "files" in options:
            from quara.creds.manager.adapters.storages.file_storage import (
                FileStorageBackend,
                FileStorageOptions,
            )

            return FileStorageBackend(FileStorageOptions(**options["files"]))
        else:
            raise ValueError("Invalid file storage options")
