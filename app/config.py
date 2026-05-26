import json
import os
import logging
from pathlib import Path
from encryption import EncryptionManager

logger = logging.getLogger(__name__)


class ConfigManager:
    ENCRYPTED_FIELDS = {"xg_password"}

    def __init__(self, path: str):
        self.path = Path(path)
        self._data: dict = {}
        self.encryption = EncryptionManager()
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Failed to load config: {e}")
                self._data = {}
        else:
            self._data = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))

    def get(self, key: str, default=None):
        value = self._data.get(key, default)
        if key in self.ENCRYPTED_FIELDS and value:
            try:
                return self.encryption.decrypt(value)
            except Exception as e:
                logger.error(f"Failed to decrypt {key}: {e}")
                return default
        return value

    def set(self, key: str, value) -> None:
        if key in self.ENCRYPTED_FIELDS and value:
            value = self.encryption.encrypt(value)
        self._data[key] = value
        self._save()
