import aiohttp
from aiohttp import ClientRequest, ClientResponse, helpers, hdrs
from aiohttp.connector import Connection
from aiohttp.http_writer import HttpVersion10, HttpVersion11
from aiohttp.http import StreamWriter
import base64
import functools
import logging
import zipfile
from io import BytesIO
import os
import ssl
from multidict import CIMultiDict

from cryptography.utils import int_to_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.models import TLS, MakeRequestParams
import app.key_loader as key_loader


def _safe_header(string: str) -> str:
    if "\r" in string or "\n" in string:
        raise ValueError(
            "Newline or carriage return detected in headers. "
            "Potential header injection attack."
        )
    return string


def _py_serialize_headers(status_line: str, headers: "CIMultiDict[str]") -> bytes:
    headers_gen = (_safe_header(k) + ": " + _safe_header(v) for k, v in headers.items())
    line = status_line + "\r\n" + "\r\n".join(headers_gen) + "\r\n\r\n"
    return line.encode("latin-1")


class Latin1HeadersStreamWriter(StreamWriter):
    async def write_headers(
        self, status_line: str, headers: "CIMultiDict[str]"
    ) -> None:
        """Write request/response status and headers."""
        if self._on_headers_sent is not None:
            await self._on_headers_sent(headers)

        # status + headers
        buf = _py_serialize_headers(status_line, headers)
        self._write(buf)


class Latin1HeadersClientRequest(ClientRequest):
    async def send(self, conn: "Connection") -> "ClientResponse":
        # Specify request target:
        # - CONNECT request must send authority form URI
        # - not CONNECT proxy must send absolute form URI
        # - most common is origin form URI
        if self.method == hdrs.METH_CONNECT:
            connect_host = self.url.raw_host
            assert connect_host is not None
            if helpers.is_ipv6_address(connect_host):
                connect_host = f"[{connect_host}]"
            path = f"{connect_host}:{self.url.port}"
        elif self.proxy and not self.is_ssl():
            path = str(self.url)
        else:
            path = self.url.raw_path
            if self.url.raw_query_string:
                path += "?" + self.url.raw_query_string

        protocol = conn.protocol
        assert protocol is not None
        writer = Latin1HeadersStreamWriter(
            protocol,
            self.loop,
            on_chunk_sent=functools.partial(
                self._on_chunk_request_sent, self.method, self.url
            ),
            on_headers_sent=functools.partial(
                self._on_headers_request_sent, self.method, self.url
            ),
        )

        if self.compress:
            writer.enable_compression(self.compress)

        if self.chunked is not None:
            writer.enable_chunking()

        # set default content-type
        if (
            self.method in self.POST_METHODS
            and hdrs.CONTENT_TYPE not in self.skip_auto_headers
            and hdrs.CONTENT_TYPE not in self.headers
        ):
            self.headers[hdrs.CONTENT_TYPE] = "application/octet-stream"

        # set the connection header
        connection = self.headers.get(hdrs.CONNECTION)
        if not connection:
            if self.keep_alive():
                if self.version == HttpVersion10:
                    connection = "keep-alive"
            else:
                if self.version == HttpVersion11:
                    connection = "close"

        if connection is not None:
            self.headers[hdrs.CONNECTION] = connection

        # status + headers
        status_line = "{0} {1} HTTP/{2[0]}.{2[1]}".format(
            self.method, path, self.version
        )
        await writer.write_headers(status_line, self.headers)

        self._writer = self.loop.create_task(self.write_bytes(writer, conn))

        response_class = self.response_class
        assert response_class is not None
        self.response = response_class(
            self.method,
            self.original_url,
            writer=self._writer,
            continue100=self._continue,
            timer=self._timer,
            request_info=self.request_info,
            traces=self._traces,
            loop=self.loop,
            session=self._session,
        )
        return self.response


class ServerPlatform:
    OB_CERTS_DIR = os.path.abspath(
        os.environ.get("OB_CERTS_DIR", "/app/open_banking_certs")
    )

    def __init__(self, key_loader: key_loader.KeyLoader):
        self.key_loader = key_loader

    @staticmethod
    def _set_tls_version_for_ssl_context(
        ssl_context: ssl.SSLContext, tls_version: str | None = None
    ) -> None:
        if tls_version is None:
            return
        tls_map = {
            "TLSv1": ssl.TLSVersion.TLSv1,
            "TLSv1_1": ssl.TLSVersion.TLSv1_1,
            "TLSv1_2": ssl.TLSVersion.TLSv1_2,
            "TLSv1_3": ssl.TLSVersion.TLSv1_3,
        }
        forced_tls_version = tls_map.get(tls_version)
        if forced_tls_version is not None:
            ssl_context.minimum_version = forced_tls_version
            ssl_context.maximum_version = forced_tls_version

    def get_ssl_context(self, tls: TLS | None) -> ssl.SSLContext:
        ssl_context = ssl.create_default_context()
        if tls:
            ssl_context = self.key_loader.update_ssl_context(ssl_context, tls)
            self._set_tls_version_for_ssl_context(ssl_context, tls.tls_version)
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

    async def make_request(
        self, request: MakeRequestParams, follow_redirects: bool | None = True
    ):
        url = request.origin + request.path
        data = request.body.encode()
        request_headers = dict(request.headers)
        logging.debug(
            "Request(%r, %r, params=%r, headers=%r, method=%r)",
            url,
            data,
            request.query,
            request_headers,
            request.method,
        )
        ssl_context = self.get_ssl_context(request.tls)
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60.0),
                request_class=Latin1HeadersClientRequest,
            ) as session:
                async with session.request(
                    method=request.method,
                    url=url,
                    params=request.query,
                    data=data,
                    headers=request_headers,
                    ssl=ssl_context,
                    allow_redirects=follow_redirects,
                ) as response:
                    peercert = None
                    if response.connection and response.connection.transport:
                        sslobj = response.connection.transport.get_extra_info("ssl_object")
                        if sslobj:
                            peercert = sslobj.getpeercert(True)
                            if peercert:
                                peercert = ssl.DER_cert_to_PEM_cert(peercert)
                    if (
                        response.headers.get("Content-Type")
                        == "application/octet-stream"
                    ):
                        response_text = self._handle_binary_response(
                            await response.read()
                        ).decode("utf-8")
                    else:
                        response_text = await response.text()
                    response_headers = [
                        (name, value) for name, value in response.headers.items()
                    ]
                    return {
                        "status": response.status,
                        "response": response_text,
                        "headers": response_headers,
                        "certificate": peercert,
                    }
        except aiohttp.ClientResponseError as e:
            response_headers = (
                [(name, value) for name, value in e.headers.items()]
                if e.headers
                else []
            )
            return {
                "status": e.status,
                "response": e.message,
                "headers": response_headers,
            }

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

    async def sign_with_key(
        self,
        data: str | bytes,
        key_path: str,
        hash_algorithm: str | None = None,
        crypto_algorithm: str | None = None,
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
        hash_algorithms_map = {
            "SHA256": hashes.SHA256,
            "SHA512": hashes.SHA512,
        }
        try:
            hash_obj = hash_algorithms_map[hash_algorithm]
        except AttributeError:
            raise AttributeError(
                f"Wrong hash algorithm: {hash_algorithm}. Allowed: {list(hash_algorithms_map.keys())}"
            )

        data = self._force_bytes(data)
        key = load_pem_private_key(
            self.key_loader.get_content(key_path),
            (lambda p: p.encode("utf-8") if p is not None else None)(
                key_loader.read_key_password(key_path)
            ),
            True,
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


def get_server_platform() -> ServerPlatform:
    key_loader_env = os.environ.get("KEY_LOADER", "FILE")
    match key_loader_env:
        case "FILE":
            kl = key_loader.FileKeyLoader()
        case "ENV":
            kl = key_loader.EnvKeyLoader()
        case _:
            raise ValueError(f"Unsupported key loader: {key_loader_env}")
    return ServerPlatform(kl)
