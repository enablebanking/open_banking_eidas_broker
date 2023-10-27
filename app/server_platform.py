import base64
import gzip
import logging
import zipfile
from io import BytesIO
import os
import re
import ssl
from typing import Union, Optional
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    Request,
    urlopen,
    build_opener,
    install_opener,
    HTTPRedirectHandler,
    HTTPSHandler,
)

from cryptography.utils import int_to_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from models import Pair, TLS, ApiRequest


def _params_to_pairs(params: list[Pair]) -> list[tuple[str, str]]:
    return [(param.name, param.value) for param in params] if params else []


def _read_key_password(key_path: str) -> str | None:
    return os.environ.get(re.sub("[\-\.\/]", "_", key_path).upper() + "_PASSWORD")


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        logging.debug("Got redirect")
        return None


# For the future: extend this class from enablebanking's platform
class ServerPlatform:
    OB_CERTS_DIR = os.environ.get("OB_CERTS_DIR", "/app/open_banking_certs")

    def get_ssl_context(self, tls: TLS | None) -> ssl.SSLContext:
        if tls:
            self.update_tls_paths(tls)
            ssl_context = ssl.create_default_context()
            ssl_context.load_cert_chain(
                os.path.join(self.OB_CERTS_DIR, tls.cert_path),
                os.path.join(self.OB_CERTS_DIR, tls.key_path),
                lambda: _read_key_password(_tls.key_path)
            )
            if tls.ca_cert_path:
                ssl_context.load_verify_locations(os.path.join(self.OB_CERTS_DIR, tls.ca_cert_path))

            if os.getenv("verify_cert", False):
                if not tls.ca_cert_path:
                    raise Exception(
                        "ca_cert_path must be specified when verify_cert is set"
                    )
                ssl_context.verify_flags = ssl.CERT_REQUIRED
            else:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
        else:
            ssl_context = ssl._create_unverified_context()
        return ssl_context

    def _handle_binary_response(self, response: bytes) -> bytes:
        try:
            archive = zipfile.ZipFile(BytesIO(response), "r")
            # assume that there is only one file in the archive
            logging.debug(f"Archive contains following files: {archive.namelist()}")
            return archive.read(archive.namelist()[0])
        except zipfile.BadZipFile:
            logging.error("Response is not a zip archive")
            return response

    def makeRequest(self, request: ApiRequest, follow_redirects: Optional[bool] = True):
        url = request.origin + request.path
        query = urlencode(_params_to_pairs(request.query))
        data = request.body.encode()
        headers = dict((a, b) for a, b in _params_to_pairs(request.headers))
        if query:
            url += "?" + query
        logging.debug(
            "Request(%r, %r, headers=%r, method=%r)", url, data, headers, request.method
        )
        req = Request(url, data=data, headers=headers, method=request.method)
        ssl_context = self.get_ssl_context(request.tls)
        https_opener = HTTPSHandler(
            context=ssl_context
        )  # for some reason urllib cant install your custom redirect opener if you have ssl context
        if follow_redirects:
            opener = build_opener(https_opener)
        else:
            opener = build_opener(
                https_opener, NoRedirectHandler
            )  # so we just create opener with both https and no redirect handler
        install_opener(opener)
        try:
            with urlopen(req, timeout=60) as f:
                response_info = f.info()
                logging.debug("%r", response_info.items())
                content_type = response_info.get("Content-Type")
                if content_type == "application/octet-stream":
                    response_bytes = self._handle_binary_response(f.read())
                else:
                    encoding = response_info.get("content-encoding", None)
                    if encoding and encoding.lower() == "gzip":
                        response_bytes = gzip.decompress(f.read()).decode("utf-8")
                    else:
                        response_bytes = f.read().decode("utf-8")
                logging.debug("%d %r", f.status, response_bytes)
                headers = [(name, value) for name, value in response_info.items()]
                return {"status": f.status, "response": response_bytes, "headers": headers}
        except HTTPError as e:
            encoding = e.headers["content-encoding"]
            if encoding and encoding.lower() == "gzip":
                response = gzip.decompress(e.fp.read()).decode("utf-8")
            else:
                response = e.fp.read().decode("utf-8")
            logging.error("%d %r", e.status, response)
            headers = [(name, value) for name, value in e.headers.items()]
            return {"status": e.status, "response": response, "headers": headers}

    @staticmethod
    def _force_bytes(value: str | bytes) -> bytes:
        """Convert value to bytes if necessary

        Arguments:
            value {String, Bytes} -- Some value to convert to bytes

        Raises:
            TypeError: If wrong value is passed

        Returns:
            Bytes -- Value converted to bytes]
        """
        if isinstance(value, str):
            return value.encode("utf-8")
        return value

    def _prepare_key(self, key: bytes, password: str | None = None) -> PrivateKeyTypes:
        """Create a key out of .pem key

        Arguments:
            key {String, Bytes} -- Private/Public key value

        Keyword Arguments:
            password {String} -- Password to a private key (default: {None})

        Raises:
            TypeError: If wrong value is provided for a key

        Returns:
            cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey -- Private key class instance
        """
        key = self._force_bytes(key)

        backend: Backend = default_backend()

        return backend.load_pem_private_key(key, password, True)

    @staticmethod
    def _decode_signature(signature: bytes, hash_algorithm: str) -> bytes:
        hash_algorithms_map = {"SHA256": 256}
        try:
            num_bits = hash_algorithms_map[hash_algorithm]
        except KeyError:
            raise ValueError(
                f"Wrong hash algorithm: {hash_algorithm}. Allowed: {list(hash_algorithms_map.keys())}"
            )
        num_bytes = (num_bits + 7) // 8
        r, s = decode_dss_signature(signature)
        return int_to_bytes(r, num_bytes) + int_to_bytes(s, num_bytes)

    def signWithKey(
        self,
        data: Union[str, bytes],
        key_path: str,
        hash_algorithm: Optional[str] = None,
        crypto_algorithm: Optional[str] = None,
    ) -> str:
        """Sign passed data with private key

        Arguments:
            data {String, Bytes} -- Data to be signed
            key_path {String} -- Path to a file with a private key
            hash_algorithm {String} -- Hash algorithm to use.
                                       If not provided then `sha256` will be used

        Returns:
            String -- Base64 encoded signed with a private key string
        """
        if hash_algorithm is None:
            hash_algorithm = "SHA256"
        hash_algorithm = hash_algorithm.upper()
        hash_algorithms_map = {"SHA256": hashes.SHA256}
        try:
            hash_obj = hash_algorithms_map[hash_algorithm]
        except AttributeError:
            raise AttributeError(
                f"Wrong hash algorithm: {hash_algorithm}. Allowed: {list(hash_algorithms_map.keys())}"
            )

        data = self._force_bytes(data)
        key = self._prepare_key(
            open(os.path.join(self.OB_CERTS_DIR, key_path), "rb").read(),
            _read_key_password(key_path)
        )
        signature = b""
        if isinstance(key, RSAPrivateKey):
            if crypto_algorithm and crypto_algorithm == "PS":
                signature = key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hash_obj()), salt_length=hash_obj.digest_size
                    ),
                    hash_obj(),
                )
            else:
                signature = key.sign(data, padding.PKCS1v15(), hash_obj())
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            signature = key.sign(data, ec.ECDSA(hash_obj()))
            signature = self._decode_signature(signature, hash_algorithm)
        return base64.b64encode(signature).decode("utf8")
