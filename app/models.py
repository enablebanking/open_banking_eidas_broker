from typing import NamedTuple
from pydantic import BaseModel


class Pair(NamedTuple):
    name: str
    value: str


class BaseRequest(BaseModel):
    params: BaseModel


class SignParams(BaseModel):
    data: str
    key_id: str
    hash_algorithm: str | None = None
    crypto_algorithm: str | None = None


class SignRequest(BaseRequest):
    params: SignParams


class TLS(BaseModel):
    cert_path: str
    key_path: str
    ca_cert_path: str | None = None
    key_password: str | None = None


class MakeRequestParams(BaseModel):
    method: str
    origin: str
    path: str
    query: list[tuple[str, str]] = []
    body: str = ""
    headers: list[tuple[str, str]] = []
    tls: TLS | None = None


class MakeRequestData(BaseModel):
    request: MakeRequestParams
    follow_redirects: bool | None = True


class MakeRequestRequest(BaseRequest):
    params: MakeRequestData


class ApiRequest:
    def __init__(
        self,
        method: str,
        origin: str,
        path: str,
        headers: list[Pair] | None = None,
        query: list[Pair] | None = None,
        body: str | None = None,
        tls: TLS | None = None,
    ):
        if body is None:
            body = ""
        self.method = method
        self.origin = origin
        self.path = path
        self.headers = headers if ((headers is not None)) else []
        self.query = query if ((query is not None)) else []
        self.body = body
        self.tls = tls
