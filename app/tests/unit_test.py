import os
import pytest
from unittest.mock import patch
import ssl

from . import utils

os.environ["OB_CERTS_DIR"] = "app/tests"
from .. import main, server_platform, key_loader

pytest_plugins = ("pytest_asyncio",)


def test_get_server_platform():
    platform = server_platform.get_server_platform()
    assert isinstance(platform, server_platform.ServerPlatform)
    assert isinstance(platform.key_loader, key_loader.FileKeyLoader)

    os.environ["KEY_LOADER"] = "FILE"
    platform = server_platform.get_server_platform()
    assert isinstance(platform, server_platform.ServerPlatform)
    assert isinstance(platform.key_loader, key_loader.FileKeyLoader)

    os.environ["KEY_LOADER"] = "ENV"
    platform = server_platform.get_server_platform()
    assert isinstance(platform, server_platform.ServerPlatform)
    assert isinstance(platform.key_loader, key_loader.EnvKeyLoader)
    del os.environ["KEY_LOADER"]


def test_file_key_loader_get_content():
    loader = key_loader.FileKeyLoader()
    file_path = "private.key"
    content = loader.get_content(file_path)
    assert (
        content
        == open(os.path.join(os.environ["OB_CERTS_DIR"], file_path), "rb").read()
    )

    with pytest.raises(FileNotFoundError):
        loader.get_content("nonexistent.crt")


def test_file_key_loader_update_ssl_context():
    loader = key_loader.FileKeyLoader()
    context = ssl.create_default_context()
    tls = main.models.TLS(cert_path="public.crt", key_path="private.key")
    with patch.object(context, "load_cert_chain") as mock_load_cert_chain:
        loader.update_ssl_context(context, tls)
        args, _ = mock_load_cert_chain.call_args
        assert args[0] == os.path.abspath(
            os.path.join(os.environ["OB_CERTS_DIR"], tls.cert_path)
        )
        assert args[1] == os.path.abspath(
            os.path.join(os.environ["OB_CERTS_DIR"], tls.key_path)
        )
        assert args[2] == None

    context = ssl.create_default_context()
    tls = main.models.TLS(cert_path="public.crt", key_path="encrypted_private.key")
    with pytest.raises(OSError):
        loader.update_ssl_context(context, tls)

    context = ssl.create_default_context()
    tls = main.models.TLS(cert_path="public.crt", key_path="encrypted_private.key")
    os.environ["ENCRYPTED_PRIVATE_KEY_PASSWORD"] = "1111"
    loader.update_ssl_context(context, tls)
    del os.environ["ENCRYPTED_PRIVATE_KEY_PASSWORD"]


def test_env_key_loader_get_content():
    loader = key_loader.EnvKeyLoader()
    content = "value"
    os.environ["KEY_CRED"] = content
    assert loader.get_content("KEY") == content.encode()


def test_env_key_loader_update_ssl_context():
    loader = key_loader.EnvKeyLoader()
    context = ssl.create_default_context()
    os.environ["PUBLIC_CERT_CRED"] = open(
        os.path.join(os.environ["OB_CERTS_DIR"], "public.crt")
    ).read()
    os.environ["PRIVATE_KEY_CRED"] = open(
        os.path.join(os.environ["OB_CERTS_DIR"], "private.key")
    ).read()
    tls = main.models.TLS(cert_path="PUBLIC_CERT", key_path="PRIVATE_KEY")
    loader.update_ssl_context(context, tls)

    os.environ["ENCRYPTED_PRIVATE_KEY_CRED"] = open(
        os.path.join(os.environ["OB_CERTS_DIR"], "encrypted_private.key")
    ).read()
    tls = main.models.TLS(cert_path="PUBLIC_CERT", key_path="ENCRYPTED_PRIVATE_KEY")
    with pytest.raises(OSError):
        loader.update_ssl_context(context, tls)

    os.environ["ENCRYPTED_PRIVATE_KEY_PASSWORD"] = "1111"
    loader.update_ssl_context(context, tls)


@pytest.mark.asyncio
async def test_sign_with_key():
    platform = server_platform.get_server_platform()
    data = "test"
    key_path = os.path.abspath(os.path.join(os.environ["OB_CERTS_DIR"], "private.key"))
    cert_path = os.path.abspath(os.path.join(os.environ["OB_CERTS_DIR"], "public.crt"))
    signature = await platform.sign_with_key(data, key_path)
    assert utils.verify_signature(signature, data, cert_path)

    key_path = os.path.abspath(
        os.path.join(os.environ["OB_CERTS_DIR"], "encrypted_private.key")
    )
    with pytest.raises(TypeError):
        await platform.sign_with_key(data, key_path)

    # patch, because "read_key_password" depends on a key path
    with patch.object(key_loader, "read_key_password", return_value="1111"):
        signature = await platform.sign_with_key(data, key_path)
        assert utils.verify_signature(signature, data, cert_path)
