import ssl
from typing import Dict, Any
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# requests used as an example for sending request. You can safely use urllib
import requests

HOST = "https://localhost"
BROKER_CLIENT_CERT_PATH = "broker_client_tls/client.crt"
BROKER_CLIENT_KEY_PATH = "broker_client_tls/client.key"
BROKER_CA_CERT_PATH = "broker_client_tls/ca.crt"


# All data in the requests should be passed as json, where all payload should be inside `params` field:
# {'params': 'some_important_information'}


def sign() -> str:
    res = requests.post(
        HOST + "/sign",
        json={
            "params": {
                "data": "test",
                "key_id": "seal.key",
                "crypto_algorithm": "PS",
            },
        },
        headers={"Content-Type": "application/json"},
        cert=(BROKER_CLIENT_CERT_PATH, BROKER_CLIENT_KEY_PATH),
        verify=BROKER_CA_CERT_PATH,
    )
    return res.json()["result"]


def make_request_urllib() -> Dict[Any, Any]:
    req = Request(
        HOST + "/makeRequest",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(
            {
                "params": {
                    "request": {
                        "method": "POST",
                        "origin": "https://postman-echo.com",
                        "path": "/post",
                        "headers": [],
                        # 'query': [],
                        # 'body': '',
                    }
                }
            }
        ).encode(),
    )
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_cert_chain(BROKER_CLIENT_CERT_PATH, BROKER_CLIENT_KEY_PATH)
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.load_verify_locations(BROKER_CA_CERT_PATH)
    try:
        with urlopen(req, context=ssl_context) as r:
            response_info = r.info()
            proxy_response = r.read().decode("utf-8")
            return json.loads(proxy_response)["result"]
    except HTTPError as e:
        proxy_response = e.fp.read().decode("utf-8")
        return json.loads(proxy_response)


if __name__ == "__main__":
    # You can uncomment these functions one by one and check their responses
    response = sign()
    # response = make_request_urllib()
    print(response)
