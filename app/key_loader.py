from abc import ABC, abstractmethod
import ssl
import os
import re
from tempfile import NamedTemporaryFile

from app.models import TLS


OB_CERTS_DIR = os.path.abspath(
    os.environ.get("OB_CERTS_DIR", "/app/open_banking_certs")
)
PASSWORD_SUFFIX = "_PASSWORD"
CREDENTIAL_SUFFIX = "_CRED"  # used for both public certificates and private keys


def read_key_password(key_path: str) -> str | None:
    return os.environ.get(re.sub(r"[\-\.\/]", "_", key_path).upper() + PASSWORD_SUFFIX)


class KeyLoader(ABC):
    @abstractmethod
    def get_content(self, name: str) -> bytes: ...

    @abstractmethod
    def update_ssl_context(
        self, context: ssl.SSLContext, tls: TLS
    ) -> ssl.SSLContext: ...


class FileKeyLoader(KeyLoader):
    def _get_ob_certs_file_path(self, path: str) -> str:
        abspath = os.path.abspath(os.path.join(OB_CERTS_DIR, path))
        if os.path.commonpath([OB_CERTS_DIR, abspath]) != OB_CERTS_DIR:
            raise ValueError(
                f"{path} is not inside open banking certificates directory"
            )
        return abspath

    def get_content(self, name: str) -> bytes:
        with open(self._get_ob_certs_file_path(name), "rb") as f:
            return f.read()

    def update_ssl_context(self, context: ssl.SSLContext, tls: TLS) -> ssl.SSLContext:
        context.load_cert_chain(
            self._get_ob_certs_file_path(tls.cert_path),
            self._get_ob_certs_file_path(tls.key_path),
            read_key_password(tls.key_path),
        )

        return context


class EnvKeyLoader(KeyLoader):
    def get_content(self, name: str) -> bytes:
        if not name.endswith(CREDENTIAL_SUFFIX):
            name += CREDENTIAL_SUFFIX
        return os.environ[name].encode()

    def update_ssl_context(self, context: ssl.SSLContext, tls: TLS) -> ssl.SSLContext:
        with NamedTemporaryFile() as cert_file, NamedTemporaryFile() as key_file:
            cert_file.write(self.get_content(tls.cert_path))
            key_file.write(self.get_content(tls.key_path))
            cert_file.flush()
            key_file.flush()
            context.load_cert_chain(
                cert_file.name,
                key_file.name,
                read_key_password(tls.key_path),
            )
        return context
