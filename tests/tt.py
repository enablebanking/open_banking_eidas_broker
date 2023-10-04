import gzip
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


def make_request():
    url = "http://localhost:8000/file"
    req = Request(url, headers={"Accept-Encoding": "gzip", "Accept": "application/octet-stream"})
    with urlopen(req) as res:
        response_info = res.info()
        encoding = response_info.get("content-encoding", None)
        content_type = response_info.get("content-type", None)
        print(content_type)
        if encoding and encoding.lower() == "gzip":
            response = gzip.decompress(res.read()).decode("utf-8")
        else:
            response = res.read().decode("utf-8")
        print(response)


if __name__ == "__main__":
    make_request()
