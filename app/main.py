from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.server_platform import get_server_platform
from app import models


app = FastAPI(title="Open Banking eIDAS broker")
# We could pass these files' paths from environment variables
platform = get_server_platform()


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
    return {
        "result": await platform.sign_with_key(
            request.params.data,
            request.params.key_id,
            hash_algorithm=request.params.hash_algorithm,
            crypto_algorithm=request.params.crypto_algorithm,
        )
    }


@app.post(
    "/makeRequest",
    description="Makes a request to a given origin, path and method. Uses TLS if provided",
    response_model=models.MakeRequestResponse,
)
async def make_request(request: models.MakeRequestRequest):
    return {
        "result": await platform.make_request(
            request.params.request, request.params.follow_redirects
        )
    }


@app.get("/health", description="Health check. Returns 200 if service is up")
async def health():
    return {"result": "ok"}
