from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class BaseRequest(BaseModel):
    params: Any


class HashAlgorithm(str, Enum):
    SHA256 = "SHA256"
    SHA512 = "SHA512"


class CryptoAlgorithm(str, Enum):
    RS = "RS"
    PS = "PS"


class SignParams(BaseModel):
    data: str = Field(..., description="Data to sign")
    key_id: str = Field(
        ..., description="Key ID. Identification of a key (path to a key) to sign with"
    )
    hash_algorithm: HashAlgorithm | None = Field(
        HashAlgorithm.SHA256, description="Hash algorithm to use"
    )
    crypto_algorithm: CryptoAlgorithm | None = Field(
        CryptoAlgorithm.RS, description="Crypto algorithm to use"
    )


class SignRequest(BaseRequest):
    params: SignParams


class SignResponse(BaseModel):
    result: str = Field(..., description="Base64 encoded signature")


class TLS(BaseModel):
    cert_path: str
    key_path: str
    ca_cert_path: str | None = None


class MakeRequestParams(BaseModel):
    method: str = Field(..., description="HTTP method", example="GET")
    origin: str = Field(
        ..., description="Origin of the request", example="https://postman-echo.com"
    )
    path: str = Field(..., description="Path of the request", example="/get")
    query: list[tuple[str, str]] = Field(
        default_factory=list, description="Query parameters", example=[("foo", "bar")]
    )
    body: str = Field(
        default="", description="Body of the request", example='{"foo": "bar"}'
    )
    headers: list[tuple[str, str]] = Field(
        default_factory=list,
        description="Headers of the request",
        example=[("Content-Type", "application/json")],
    )
    tls: TLS | None = Field(
        default=None,
        description="TLS configuration",
        example={"cert_path": "cert.pem", "key_path": "key.pem"},
    )


class MakeRequestData(BaseModel):
    request: MakeRequestParams
    follow_redirects: bool | None = Field(
        default=True,
        description="Flag to follow redirects. If set to false then 3XX responses will be returned as is",
    )


class MakeRequestRequest(BaseRequest):
    params: MakeRequestData


class MakeRequestResponseResult(BaseModel):
    status: int = Field(..., description="HTTP status code")
    headers: list[tuple[str, str]] = Field(
        default_factory=list,
        description="Response headers",
        example=[("Content-Type", "application/json")],
    )
    response: str = Field(
        default="", description="Response body", example='{"foo": "bar"}'
    )


class MakeRequestResponse(BaseModel):
    result: MakeRequestResponseResult
