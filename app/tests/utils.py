import base64
import requests
from typing import Any, NamedTuple, Type
from . import config

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey,
)
from cryptography.x509 import load_pem_x509_certificate


class TLS(NamedTuple):
    cert_path: str
    key_path: str


class Pair(NamedTuple):
    name: str
    value: str


class Response(NamedTuple):
    status: int
    headers: list[Pair]
    body: str


def make_request(
    method: str,
    origin: str,
    path: str,
    headers: list[Pair] | None = None,
    query: list[Pair] | None = None,
    body: str | None = None,
    tls: TLS | None = None,
    follow_redirects: bool | None = True,
) -> Response:
    if headers is None:
        headers = []
    if query is None:
        query = []
    if body is None:
        body = ""
    request_body: dict[str, Any] = {
        "params": {
            "request": {
                "method": method,
                "origin": origin,
                "path": path,
                "headers": [(pair.name, pair.value) for pair in headers],
                "query": [(pair.name, pair.value) for pair in query],
                "body": body,
                "tls": tls,
            },
            "follow_redirects": follow_redirects,
        }
    }
    if tls:
        request_body["params"]["request"]["tls"] = {
            "cert_path": tls.cert_path,
            "key_path": tls.key_path,
        }
    broker_response = requests.post(
        config.BROKER_ORIGIN + "/makeRequest",
        json=request_body,
        verify=False,
        cert=(config.MTLS_CLIENT_CERT_PATH, config.MTLS_CLIENT_KEY_PATH),
        timeout=300,
    )

    broker_json = broker_response.json()
    try:
        broker_body = broker_json["result"]
    except KeyError:
        raise Exception(f"Broker response has no result: {broker_json}")
    return Response(
        status=broker_body["status"],
        headers=[Pair(name, value) for name, value in broker_body["headers"]],
        body=broker_body["response"],
    )


def sign(
    data: str,
    key_id: str,
    hash_algorithm: str = "SHA256",
    crypto_algorithm: str = "RS",
) -> str:
    broker_response = requests.post(
        config.BROKER_ORIGIN + "/sign",
        json={
            "params": {
                "data": data,
                "key_id": key_id,
                "hash_algorithm": hash_algorithm,
                "crypto_algorithm": crypto_algorithm,
            }
        },
        verify=False,
        cert=(config.MTLS_CLIENT_CERT_PATH, config.MTLS_CLIENT_KEY_PATH),
    )
    broker_json = broker_response.json()
    try:
        broker_body = broker_json["result"]
    except KeyError:
        raise Exception(f"Broker response has no result: {broker_json}")
    return broker_body


def _get_hash_algorithm(hash_algorithm: str) -> Type[hashes.HashAlgorithm]:
    hash_algorithm = hash_algorithm.upper()
    hash_algorithms_map = {
        "SHA256": hashes.SHA256,
        "SHA512": hashes.SHA512,
    }
    try:
        return hash_algorithms_map[hash_algorithm]
    except AttributeError:
        raise AttributeError(
            f"Wrong hash algorithm: {hash_algorithm}. Allowed: {list(hash_algorithms_map.keys())}"
        )


def _base64_add_padding(data: str) -> str:
    return data + "=" * ((4 - len(data) % 4) % 4)


def verify_signature(
    signature: str,
    message: str,
    cert_path: str,
    hash_algorithm: str | None = "SHA256",
    crypto_algorithm: str | None = "RS",
) -> bool:
    if hash_algorithm is None:
        hash_algorithm = "SHA256"
    if crypto_algorithm is None:
        crypto_algorithm = "RS"
    hash_obj = _get_hash_algorithm(hash_algorithm)
    signature_bytes = base64.urlsafe_b64decode(_base64_add_padding(signature).encode())
    encoded_message = message.encode()
    public_cert = load_pem_x509_certificate(open(cert_path, "rb").read())
    public_key: RSAPublicKey = public_cert.public_key()  # type: ignore
    try:
        if crypto_algorithm == "PS":
            public_key.verify(
                signature_bytes,
                encoded_message,
                padding.PSS(
                    mgf=padding.MGF1(hash_obj()), salt_length=hash_obj.digest_size
                ),
                hash_obj(),
            )
        elif crypto_algorithm == "RS":
            public_key.verify(
                signature_bytes, encoded_message, padding.PKCS1v15(), hash_obj()
            )
        else:
            raise ValueError(f"{crypto_algorithm} crypto algorithm is not supported")

    except InvalidSignature:
        return False
    return True
