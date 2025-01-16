import logging
import json

import requests
import pytest

from . import config, utils


def test_health():
    # health check is expected to be available over HTTP
    broker_origin = config.BROKER_ORIGIN.replace("https://", "http://")
    response = requests.get(broker_origin + "/health")
    assert response.status_code == 200
    assert response.text == '{"result":"ok"}'

    response = requests.get(config.BROKER_ORIGIN + "/health", verify=False)
    assert response.status_code == 200
    assert response.text == '{"result":"ok"}'


def test_mtls_request():
    response = requests.get(
        config.BROKER_ORIGIN + "/",
        verify=False,
        cert=(config.MTLS_CLIENT_CERT_PATH, config.MTLS_CLIENT_KEY_PATH),
    )
    logging.info(response.text)
    assert response.status_code == 200
    assert response.text == '{"result":"eIDAS broker"}'


def test_regular_request():
    response = utils.make_request("GET", config.MOCK_ORIGIN, "/")
    logging.info(response.body)
    assert response.status == 200
    assert response.body == '{"message":"Hello World"}'


def test_request_with_tls():
    response = utils.make_request(
        "GET",
        config.MOCK_ORIGIN,
        "/redirect",
        tls=utils.TLS(config.QWAC_CERT_NAME, config.QWAC_KEY_NAME),
    )
    logging.info(response.body)
    assert response.status == 200


def test_follow_redirects():
    response = utils.make_request(
        "GET", config.MOCK_ORIGIN, "/redirect", follow_redirects=True
    )
    logging.info(response.body)
    assert response.status == 200
    assert response.body == '{"message":"Hello World"}'

    response = utils.make_request(
        "GET", config.MOCK_ORIGIN, "/redirect", follow_redirects=False
    )
    logging.info(response.body)
    assert response.status == 307
    for header in response.headers:
        if header.name.lower() == "location":
            break
    else:
        raise Exception("Location header not found")
    assert response.body == ""


def test_gzipped_response():
    response = utils.make_request(
        "GET",
        config.MOCK_ORIGIN,
        "/gzip",
        headers=[utils.Pair("Accept-Encoding", "gzip")],
    )
    logging.info(response.body)
    assert response.status == 200
    assert response.body == '{"message":"Hello World"}'


def test_file_response():
    response = utils.make_request("GET", config.MOCK_ORIGIN, "/file")
    logging.info(response.body)
    assert response.status == 200
    assert json.loads(response.body)


def test_query_parameters():
    response = utils.make_request(
        "GET",
        "https://postman-echo.com",
        "/get",
        query=[utils.Pair("foo", "bar")],
    )
    logging.info(response.body)
    assert response.status == 200
    assert json.loads(response.body)["args"]["foo"] == "bar"

    response = utils.make_request(
        "GET",
        "https://postman-echo.com",
        "/get",
        query=[utils.Pair("url", "https://example.com")],
    )
    logging.info(response.body)
    assert response.status == 200
    assert json.loads(response.body)["args"]["url"] == "https://example.com"

    response = utils.make_request(
        "GET",
        "https://postman-echo.com",
        "/get?baz=qux",
    )
    logging.info(response.body)
    assert response.status == 200
    assert json.loads(response.body)["args"]["baz"] == "qux"

    response = utils.make_request(
        "GET",
        "https://postman-echo.com/get?bar=foo",
        "",
    )
    logging.info(response.body)
    assert response.status == 200
    assert json.loads(response.body)["args"]["bar"] == "foo"


def test_rs_signature():
    payload = "test"
    signature = utils.sign(payload, config.QSEAL_KEY_NAME)
    logging.info(signature)
    assert utils.verify_signature(signature, payload, config.QSEAL_CERT_PATH)

    hash_algorithm = "SHA512"
    signature = utils.sign(
        payload, config.QSEAL_KEY_NAME, hash_algorithm=hash_algorithm
    )
    logging.info(signature)
    assert utils.verify_signature(
        signature, payload, config.QSEAL_CERT_PATH, hash_algorithm=hash_algorithm
    )


def test_ps_signature():
    payload = "test"
    crypto_algorithm = "PS"
    signature = utils.sign(
        payload, config.QSEAL_KEY_NAME, crypto_algorithm=crypto_algorithm
    )
    logging.info(signature)
    assert utils.verify_signature(
        signature, payload, config.QSEAL_CERT_PATH, crypto_algorithm=crypto_algorithm
    )

    hash_algorithm = "SHA512"
    signature = utils.sign(
        payload,
        config.QSEAL_KEY_NAME,
        hash_algorithm=hash_algorithm,
        crypto_algorithm=crypto_algorithm,
    )
    logging.info(signature)
    assert utils.verify_signature(
        signature,
        payload,
        config.QSEAL_CERT_PATH,
        hash_algorithm=hash_algorithm,
        crypto_algorithm=crypto_algorithm,
    )


def test_timeout():
    with pytest.raises(Exception) as e:
        utils.make_request("GET", config.MOCK_ORIGIN, "/timeout")
    assert "server error" in str(e)


def test_header_encoding():
    headers = {
        "unescaped": "Serviços de Certificação Electrónica S.A.",
        "escaped": "Servi\\C3\\A7os de Certifica\\C3\\A7\\C3\\A3o Electr\\C3\\B3nica S.A.",
    }
    response = utils.make_request(
        "GET",
        "https://postman-echo.com",
        "/get",
        headers=[utils.Pair(k, v) for k, v in headers.items()],
    )
    assert response.status == 200
    logging.info(response.body)
    json_body = json.loads(response.body)
    assert json_body["headers"]["unescaped"] == headers["unescaped"]
    assert json_body["headers"]["escaped"] == headers["escaped"]
