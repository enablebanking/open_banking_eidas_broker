import config
import requests
import logging
import utils
import json
import pytest


def test_health():
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
    assert json.loads(response.body) == {"some": "json"}


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


def test_signature():
    payload = "test"
    signature = utils.sign(payload, config.QSEAL_KEY_NAME)
    logging.info(signature)
    assert utils.verify_signature(signature, payload, config.QSEAL_CERT_PATH)

    crypto_algorithm = "PS"
    signature = utils.sign(
        payload, config.QSEAL_KEY_NAME, crypto_algorithm=crypto_algorithm
    )
    logging.info(signature)
    assert utils.verify_signature(
        signature, payload, config.QSEAL_CERT_PATH, crypto_algorithm=crypto_algorithm
    )


def test_timeout():
    with pytest.raises(Exception) as e:
        utils.make_request("GET", config.MOCK_ORIGIN, "/timeout")
        assert "timed out" in str(e)
