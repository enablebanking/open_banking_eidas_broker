from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

from server_platform import ServerPlatform
import models


app = FastAPI()
# We could pass these files' paths from environment variables
platform = ServerPlatform()


@app.exception_handler(Exception)
async def base_exception_handler(request: Request, exc: Exception):
    error_code = 500
    return JSONResponse(
        status_code=error_code,
        content={
            "code": error_code,
            "message": f"Internal server error",
            # Note that it is not safe to display internal error for end user
            # This is done intentionally
            "data": str(exc),
        },
    )


@app.get("/")
async def read_root():
    return {"result": "eIDAS broker"}


@app.post(
    "/sign",
    description="Signs data with a key and returns signature",
    response_model=models.SignResponse,
)
async def sign(request: models.SignRequest):
    sign_params: models.SignParams = request.params
    return {
        "result": platform.signWithKey(
            sign_params.data,
            sign_params.key_id,
            hash_algorithm=sign_params.hash_algorithm,
            crypto_algorithm=sign_params.crypto_algorithm,
        )
    }


@app.post(
    "/makeRequest",
    description="Makes a request to a given origin, path and method. Uses TLS if provided",
    response_model=models.MakeRequestResponse,
)
async def make_request(request: models.MakeRequestRequest):
    make_request_data = request.params
    make_request_params = make_request_data.request
    query = None
    if make_request_params.query:
        query = [models.Pair(name, value) for name, value in make_request_params.query]
    headers = None
    if make_request_params.headers:
        headers = [
            models.Pair(name, value) for name, value in make_request_params.headers
        ]
    api_request = models.ApiRequest(
        make_request_params.method,
        make_request_params.origin,
        make_request_params.path,
        headers=headers,
        query=query,
        body=make_request_params.body,
        tls=make_request_params.tls,
    )
    return {
        "result": platform.makeRequest(api_request, make_request_data.follow_redirects)
    }


@app.get("/health", description="Health check. Returns 200 if service is up")
async def health():
    return {"result": "ok"}
