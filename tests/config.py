import os

broker_origin = os.environ.get("BROKER_ORIGIN", None)
if not broker_origin:
    raise ValueError("BROKER_ORIGIN environment variable must be set")
BROKER_ORIGIN = broker_origin

MOCK_ORIGIN = os.environ.get("MOCK_ORIGIN", "https://eidas-mock-todjdqftaa-ez.a.run.app")
mtls_client_cert_path = os.environ.get("MTLS_CLIENT_CERT_PATH", None)
if not mtls_client_cert_path:
    raise ValueError("MTLS_CLIENT_CERT_PATH environment variable must be set")
MTLS_CLIENT_CERT_PATH = mtls_client_cert_path
mtls_client_key_path = os.environ.get("MTLS_CLIENT_KEY_PATH", None)
if not mtls_client_key_path:
    raise ValueError("MTLS_CLIENT_KEY_PATH environment variable must be set")
MTLS_CLIENT_KEY_PATH = mtls_client_key_path

qseal_cert_path = os.environ.get("QSEAL_CERT_PATH", None)
if not qseal_cert_path:
    raise ValueError("QSEAL_CERT_PATH environment variable must be set")
QSEAL_CERT_PATH = qseal_cert_path
qseal_key_name = os.environ.get("QSEAL_KEY_NAME", None)
if not qseal_key_name:
    raise ValueError("QSEAL_KEY_NAME environment variable must be set")
QSEAL_KEY_NAME = qseal_key_name
