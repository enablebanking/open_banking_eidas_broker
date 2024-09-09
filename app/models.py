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
    tls_version: str | None = None


class MakeRequestParams(BaseModel):
    method: str = Field(..., description="HTTP method", examples=["GET"])
    origin: str = Field(
        ..., description="Origin of the request", examples=["https://postman-echo.com"]
    )
    path: str = Field(..., description="Path of the request", examples=["/get"])
    query: list[tuple[str, str]] = Field(
        default_factory=list,
        description="Query parameters",
        examples=[[("foo", "bar")]],
    )
    body: str = Field(
        default="", description="Body of the request", examples=['{"foo": "bar"}']
    )
    headers: list[tuple[str, str]] = Field(
        default_factory=list,
        description="Headers of the request",
        examples=[[("Content-Type", "application/json")]],
    )
    tls: TLS | None = Field(
        default=None,
        description="TLS configuration",
        examples=[{"cert_path": "cert.pem", "key_path": "key.pem"}],
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
        examples=[[("Content-Type", "application/json")]],
    )
    response: str = Field(
        default="", description="Response body", examples=['{"foo": "bar"}']
    )
    certificate: str | None = Field(
        default=None, description="Server certificate if available", examples=['-----BEGIN CERTIFICATE-----\nMIIDnDCCAyGgAwIBAgISBH8XfncWBVHDh+CIL89ToOonMAoGCCqGSM49BAMDMDIx\nCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF\nNjAeFw0yNDA3MjUxMjAyMTFaFw0yNDEwMjMxMjAyMTBaMBwxGjAYBgNVBAMTEWVu\nYWJsZWJhbmtpbmcuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIftbwQNg\n+iK2+piedKsdJ0Y9FXEqJKfYmeDR+vYLgm0Zk30lTwoxBoI0W+OitG9BWbKdHn0G\nuNQQobykzNjboqOCAiswggInMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggr\nBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUp/xnLs/S\nxNZw8eLgBJzbkUj2QHkwHwYDVR0jBBgwFoAUkydGmAOpUWiOmNbEQkjbI79YlNIw\nVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vZTYuby5sZW5jci5v\ncmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9lNi5pLmxlbmNyLm9yZy8wMwYDVR0RBCww\nKoIRZW5hYmxlYmFua2luZy5jb22CFXd3dy5lbmFibGViYW5raW5nLmNvbTATBgNV\nHSAEDDAKMAgGBmeBDAECATCCAQUGCisGAQQB1nkCBAIEgfYEgfMA8QB3AEiw42va\npkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAABkOn8Gi4AAAQDAEgwRgIhANUN\nBFrE/0VUWfG6NbMluXprsa10C5Na8Yb2XHol2KclAiEAhvFxYa+NppZexDU7sBfb\nHr6owVFWVlj+kQ/q/ewIRh0AdgB2/4g/Crb7lVHCYcz1h7o0tKTNuyncaEIKn+Zn\nTFo6dAAAAZDp/BphAAAEAwBHMEUCIQCWS7RU9oGH7dCITs9cuAykl71iop6fBwjq\n0a8rt6T25QIgAbDXYRa+/Qp4alvBrC7XYO4Wmkz9fgv/boRif0rwbdswCgYIKoZI\nzj0EAwMDaQAwZgIxAOX17axdfXrOM43b5JkCzTVYysrG8sjmA3gDJak0xdAo+FPD\neh+L2EZT4Z6xgPsgDgIxAO7EXqyGezmUyKHS22e5O8JduHY6gzxEjZ9G9rX8pkgp\nNcTASPTExl14vvdkRG+O/Q==\n-----END CERTIFICATE-----\n']
    )


class MakeRequestResponse(BaseModel):
    result: MakeRequestResponseResult
