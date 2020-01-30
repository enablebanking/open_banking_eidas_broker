from collections import namedtuple
import os
from typing import Dict, List, Tuple, Union, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from server_platform import ServerPlatform

app = FastAPI()
# We could pass these files' paths from environment variables
platform = ServerPlatform()


class BaseRequest(BaseModel):
    params: BaseModel

class SignParams(BaseModel):
    data: str
    key_id: str
    hash_algorithm: Optional[str] = None

class SignRequest(BaseRequest):
    params: SignParams

class TLS(BaseModel):
    cert_path: str
    key_path: str
    ca_cert_path: Optional[str] = None
    key_password: Optional[str] = None

class MakeRequestParams(BaseModel):
    method: str
    origin: str
    path: str
    query: List[Tuple[str, str]] = []
    body: str = ''
    headers: List[Tuple[str, str]] = []
    tls: TLS = None

class MakeRequestData(BaseModel):
    request: MakeRequestParams

class MakeRequestRequest(BaseRequest):
    params: MakeRequestData


class ApiRequest:
    def __init__(self, method, origin, path, headers=None, query=None, body=None, tls=None):
        if (body is None):
            body = ""
        self.method = method
        self.origin = origin
        self.path = path
        self.headers = (headers if ((headers is not None)) else [])
        self.query = (query if ((query is not None)) else [])
        self.body = body
        self.tls = tls

def get_params(request):
    params = getattr(request, 'params', None)
    if not params:
        raise HTTPException(status_code=422, detail='Wrong data format. All request data must be inside `params` field')
    return params


# this endpoint left intentionally for some setup/testing
@app.get("/")
async def read_root():
    return {"Hello": "World"}

@app.post("/sign")
async def sign(request: SignRequest):
    sign_params: SignParams = get_params(request)
    return {
        'result': platform.signWithKey(sign_params.data, sign_params.key_id, sign_params.hash_algorithm)
    }

@app.post("/makeRequest")
async def make_request(request: MakeRequestRequest):
    make_request_data = get_params(request)
    make_request_params = getattr(make_request_data, 'request')
    if not make_request_params:
        raise HTTPException(status_code=422, detail='No request data. Field `request` does not exist or is empty')
    Pair = namedtuple('Pair', ['name', 'value'])
    query = None
    if make_request_params.query:
        query = [Pair(name, value) for name, value in make_request_params.query]
    headers = None
    if make_request_params.headers:
        headers = [Pair(name, value) for name, value in make_request_params.headers]
    api_request = ApiRequest(
        make_request_params.method,
        make_request_params.origin,
        make_request_params.path,
        headers=headers,
        query=query,
        body=make_request_params.body,
        tls=make_request_params.tls)
    return {
        'result': platform.makeRequest(api_request)
    }
