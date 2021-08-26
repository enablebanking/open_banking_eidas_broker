import base64
import gzip
import logging
import os
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _params_to_pairs(params):
    return [(param.name, param.value) for param in params] if params else []


# class used as a workaround for cases where server checks for case of headers (even though it shouln't)
class SafeString(str):
    def title(self):
        return self

    def capitalize(self):
        return self


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        logging.error("Got redirect")
        # raise HTTPError(req.full_url, code, msg, headers, fp)
        return None


# For the future: extend this class from enablebanking's platform
class ServerPlatform:
    PATH_PREFIX = "/app/open_banking_certs/"
    CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----"

    def update_tls_paths(self, tls):
        fields = ["cert_path", "key_path", "ca_cert_path"]
        for field in fields:
            if hasattr(tls, field):
                field_value = getattr(tls, field)
                if field_value and not field_value.startswith(self.PATH_PREFIX):
                    setattr(tls, field, os.path.join(self.PATH_PREFIX, field_value))

    def get_ssl_context(self, tls):
        if tls:
            self.update_tls_paths(tls)
            ssl_context = ssl.create_default_context()
            ssl_context.load_cert_chain(
                tls.cert_path, tls.key_path, lambda: tls.key_password
            )
            if tls.ca_cert_path:
                ssl_context.load_verify_locations(tls.ca_cert_path)

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

    def makeRequest(self, request, follow_redirects: Optional[bool] = True):
        url = request.origin + request.path
        query = urlencode(_params_to_pairs(request.query))
        data = request.body.encode()
        headers = dict((SafeString(a), b) for a, b in _params_to_pairs(request.headers))
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
            with urlopen(req) as f:
                response_info = f.info()
                logging.info("%r", response_info.items())
                encoding = response_info.get("content-encoding", None)
                if encoding and encoding.lower() == "gzip":
                    response = gzip.decompress(f.read()).decode("utf-8")
                else:
                    response = f.read().decode("utf-8")
                logging.debug("%d %r", f.status, response)
                headers = [(name, value) for name, value in response_info.items()]
                return {"status": f.status, "response": response, "headers": headers}
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
    def _force_bytes(value):
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
        elif isinstance(value, bytes):
            return value
        else:
            raise TypeError("Expected a string value")

    def _prepare_key(self, key, password=None):
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
        if isinstance(key, (str, bytes)):
            key = self._force_bytes(key)

            try:
                backend = default_backend()
                key = backend.load_pem_private_key(key, password)
            except ValueError:
                key = backend.load_pem_public_key(key)
        else:
            raise TypeError("Expecting a PEM-formatted key.")

        return key

    @staticmethod
    def _decode_signature(signature, hash_algorithm):
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
        if not key_path.startswith(self.PATH_PREFIX):
            key_path = os.path.join(self.PATH_PREFIX, key_path)
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
        key = self._prepare_key(open(key_path, "rb").read())
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

    def loadPEM(self, cert_path: str) -> str:
        """
        Loads PEM certificate data
        Be careful and try to avoid exposing private certificate data using this method
        """
        # trying to limit paths to point only to the PATH_PREFIX directory
        # need to be careful with paths containing ".."
        cert_path = os.path.normpath(cert_path)
        if not cert_path.startswith(self.PATH_PREFIX):
            cert_path = os.path.join(self.PATH_PREFIX, cert_path)

        try:
            data = open(cert_path, "r").read()
        except FileNotFoundError:
            raise ValueError("File not found")
        if not data.startswith(self.CERTIFICATE_PREFIX):
            raise ValueError("File not found")
        return data
