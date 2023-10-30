| CAUTION: This project works with highly sensitive data, thus carefully consider its configuration when using in production  |
| --------------------------------------------------------------------------------------------------------------------------- |

# Open Banking eIDAS broker

The broker service provides possibility to use eIDAS certificates *(in practice any X.509
certificates)* for generating signatures and sending HTTP requests over mTLS connections
without need to expose private keys of the certificates with the service client.

The web API of the broker service consists of 3 endpoints:

1. `POST /sign` -- for signing received data with a QSealC certificate and returning this
   signature back;
2. `POST /makeRequest` -- for making HTTP request over mutual TLS connection established with
   a QWAC certificate and returning response back;
3. `GET /health` -- for health checks to make sure that application is up and running.

For more information please refer to the [API specification](#api-specification).

Access to the broker service APIs is provided over mTLS and authentication of the client is
done based on the client certificate. The client certificate and the broker server certificate
shall be signed using the same CA certificate.

The broker service is primarily designed to be called from [Enable Banking aggregation
core](https://enablebanking.com/docs/core/latest/), which provides special `BrokerPlatform`
class offloading signing and mTLS funtionality to the broker. 

## Accessing ASPSP APIs through eIDAS broker

The flow of the calls between client, broker service and ASPSP looks like this:

```
   [Client premises]            --   [Broker service holding eIDAS keys]   --   [Open banking API (ASPSP)]

1. OB API request to be signed  ->   Signing the data using a QSealC
                                     certificate named by the client
   Request signature            <-   and returning the signature

                                     Forwarding the request to an ASPSP 
2. OB API request to be sent    ->   over mTLS established with a QWAC     ->   ASPSP gets complete API
                                     certificate named by the client            request, verifies the
                                                                                signature, and responses
   Response from the ASPSP      <-   Returning the response back to the    <-   to the broker service
                                     initiating party
```

The client may request to use different certificates (identified by URI) and to forward
arbitrary requests (to different ASPSPs).

## Generation of certificates for client - broker interaction

As mentioned earlier mTLS connector is used for securing interactions between the client
(aggregation SDK using BrokerPlatform) and the broker service. This provides adequate level
of security even when the client and the broker use are connected through Internet (the same
mechanism is used for securing open banking APIs).

The most important thing in ensuring security of the interaction is keeping private keys
securely stored and not transferring them over insecure channels. Thus CA and server private
keys shall be generated at the broker site (assuming that client and broker are located in
different networks and secure communication between them can not be guaranteed), while client
private key is generated at the client site. The client certificate is signed with CA key
at the broker site; for this certificate signing request (CSR) is transferred from the client
site to the broker, which can be done over insecure channels.

### CA

First of all CA private key shall be generated (this is done at the broker site); in the
examples below we are using OpenSSL command line utility.

```bash
openssl genrsa -out ca.key 4096
```

And CA certificate shall be generated (if necessary, replace values under `-subj` parameter
with your values).

```bash
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=FI/ST=Uusimaa/L=Helsinki/O=ExampleOrganisation/CN=ca.example.com"
```

### Server

Then server (broker) private key can be generated (again at the broker site).

```bash
openssl genrsa -out server.key 4096
```

And server CSR is to be generated. Make sure the `CN` value in the `subj` parameter matches
the host name, which will be used by the broker (in the example below `localhost` is used
for the case when we are testing broker service locally, i.e. running on the same machine,
which is used for accessing it).

```bash
openssl req -new -key server.key -out server.csr \
    -subj "/C=FI/ST=Uusimaa/L=Helsinki/O=ExampleOrganisation/CN=localhost"
```

The server certificate is to be signed with ca.key. **To ensure security DO NOT use md5 
message digest.** In the examples below we use `sha256`.

```bash
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -sha256
```

### Client

Finally a private key for the client certificate can be generated (this is done at the
client site).

```bash
openssl genrsa -out client.key 4096
```

And client CSR is generated the same way how it's done for the server (please note that
the subject should be different from the CA's subject).

```bash
openssl req -new -key client.key -out client.csr \
    -subj "/C=FI/ST=Uusimaa/L=Helsinki/O=ExampleOrganisation/CN=client.example.com"
```

Finally `client.csr` can be transferred to the site where `ca.key` is available and
signing of the client certificate with `ca.key` can be done.

```bash
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt -sha256
```

The generated client certificate (`client.crt`) can be shared back with the client.

## Verification of the certificates (optional)

You can verify server and client certifiactes against CA certificate using the following
commands.

```bash
openssl verify -purpose sslserver -CAfile ca.crt server.crt
```

```bash
openssl verify -purpose sslclient -CAfile ca.crt client.crt
```

## Building an image and starting a container

In order to build an image you need to:

1. Have docker installed
2. Go to the directory with `Dockerfile`
3. Run `docker build -t <image_name> .` (probably you need to prepend this command with `sudo`)
4. Put broker certificates you generated earlier into `broker_tls/` directory under following names:
    - `server.key`  # private key of the server (broker) certificate
    - `server.crt`  # public server (broker) certificate
    - `ca.crt`  # public CA certificate
5. Put your eIDAS certificates and their private keys, which will be used when accessing ASPSPs' APIs,
   i.e. QWAC (mTLS) and QSealC (signature) into `open_banking_certs/` directory, which will be mounted
   to the container.

   You can put certificates in an arbitrary order/names. Later you will have to provide paths to those
   certificates.

   All certificates must be in the PEM format.

    - `qwac.key`  # QWAC private key. Needed for establishing mTLS
    - `qwac.crt`  # QWAC public certificate. Needed for establishing mTLS
    - `qwac_chain.crt` (optional)  # QWAC certificate chain. Some ASPSPs require it
    - `qsealc.key`  # QSealC private key. Used for creating signatures

   If private keys are encrypted, it is possible to provide passwords for decrypting the keys by
   setting environment variables that contain the passwords. Environment variables should be named
   after the key file names, with special characters replaced by underscore symbols, and suffixed with
   `_PASSWORD`. For example, the password for `qwac.key` should be set in the environment variable
   named `QWAC_KEY_PASSWORD`.
6. Start built image:

   ```
   docker run -d \
       --name <container_name> \
       -p 443:80 \
       --mount type=bind,source="$(pwd)"/open_banking_certs/,target=/app/open_banking_certs/ \
       --mount type=bind,source="$(pwd)"/broker_tls/,target=/app/broker_tls/ \
       <image_name>
   ```

   You can also specify `verify_cert` environment variable using `-e` flag if you want you requests to
   ASPSPs to be verified against QWAC certificate chain (if it is provided).
7. You can verify that the service is running correctly by running the following command:

   ```
   curl --location 'https://localhost:443/' --key client.key --cert client-chain.crt --cacert ca.crt
   ```

   You should received `{"result":"eIDAS broker"}` in response.

## API specification

Full API specification of in the OpenAPI format is available in the [openapi.json](openapi.json) file.

When running the service locally, endpoints documentation is available at `/docs` or `/redoc`:

- `http(s)://localhost:<host_port>/docs` (Swagger UI)
- `http(s)://localhost:<host_port>/redoc` (Redoc)

### Examples

For the service invocation examples using [requests](https://requests.readthedocs.io/) library,
please refer to [example.py](examples/example.py). The example makes "proxied" calls (using
`POST /makeRequest`) to https://postman-echo.com and signs test string (using `POST /sign`) with
[example.key](examples/example.key).

### RS256 signing (RSASSA-PKCS1-v1_5 + SHA256)

`POST /sign`

Request payload:

```
{
    "params": {
        "data": "a string to sign",
        "key_id": "example.key",
        "hash_algorithm": "SHA256",
        "crypto_algorithm": "RS"
    }
}
```

Response payload:

```
{
    "result": "EK148de5pvmRoHpsd1HplHLjS4KjMrfJK4RrGyeyhourddCAXJP+7+ZBfVZYdzf8/B/KhyYgY657RyHtTy33Am9xbtJQpIr3q4xXN4VYuwnHHaqMg9GgnmUC9Cze9OCeXdo7w+TVVf6B+vDp6tFWvTnZDfd1pe+JhGIAeDDVqNvNZu+MQ8zjfO3Y/8XHFrPmfLMge6WZLCNJTHmqiJEMIEWVJXgjG1OPnZzadax+lAEL4hm/fA/biLh6etNyiwlNx7mUYCEc4gOuKjBuzNwEwc5Yp8RW/ibiX6n0UJhIlpShxag0+Lv2uanSsxna9NhMYgJuf+jjNLhTDsFwBvhMYduMCHCeO2T0d3k1VZoj0MAhT8Luc8iAWT8oJL4qqEAU6A6TqNV/pmuJfFnlyeTwxTHauDb/UtLmXErp3khu2z/yD+Y/TVFSrHjZ2QaKoXf4xsLdbFLHyzG4OwV13Pl9fK4x40oKM84i1Di4oxkAdwM4UuhEK33QCh/x5fKbq8SB2qSQOyh99/w0XoAOIviuh+U/ibLxQqDku8jyKj8Zp8femRr81cgjZonRX3uFbqOnUhjHiTpIZAZVUhhPkPM2tzkVixCp9tKRevurK8ZfJy/ZJEhMwfPgGRQn3Cn3wG09Dr9OFXHmz0cmJnAV0ZVXJnD0U4tupYGI18Vgdixdtog="
}
```

*The above example uses [example.key](examples/example.key). In case you want to verify the result you
get, you can simply compare it to the result from above, it should match exactly.*

### PS256 signing (RSASSA-PSS + SHA256)

`POST /sign`

Request payload:

```
{
    "params": {
        "data": "a string to sign",
        "key_id": "example.key",
        "hash_algorithm": "SHA256",
        "crypto_algorithm": "PS"
    }
}
```

Response payload:

```
{
    "result": "I90i3W+JdWlt21titsP14N2DUnrM5lTZtiLTQGWRMM5gBent25ktWmOaxNTQUdD0Nt8PEu9YNMKVCQ9nbWVzYYPM9Vto59hnBRD6Eb2xPQ1T0v7ecBTrkI42+1mrZ3eZbbTCLCIseWtVJXpTz34kW5kQRueTgPlTAwLzL13gQWLwzSpq4ENX4IL9EqczTnyBeOdQuIaIE7yj2bdiCsqF2M/N8Sdo1R2kcQoUGuVeBe3A3XfLtLzPvTDoyiQhHDVtxv/tnb0CmGWGm3/fm0Eu6Vr3KmO5AOAWeh01erQA4NZ88oJkexNt+IN5LoNZ2jofCu4k7uOnpPOkSizWeF4c8i/LekcwySH0DDyAMkjriGtJx0y+r7RC3zAqSdh+aWWRSpbQVOcQp32zSs4F0LsaFM1fL5JjdbyjrhHO8ymW1/coQP63hGjYvlAMAB0g+gx0Ue7IIDJmcTGcZf3o8fag9BuqZo3QKgVmS85alHs/yIJDCuNTnX83NNwgbZdrsQr3Oc4k3bdQ5CCR8zo4CNhVkS/fTXSNn1fMicTxRXcL5JRFKCQAuWM9I3p/YUb0yGN3xvL7XMXw2sbkt+RrkNsRmM9UKs54eKkIPdPeZ0Zcn5AzyKMIE9DTqwkSaqID3nKIXAaR73o9diK9WiOACim2FZ2Na2m0kz67+xfgWW+OLlw="
}
```

*The above example uses [example.key](examples/example.key). In case you want to verify the result you
get, it is necessary to generate a corresponding public key and verify result using it, because the
result will be always different due to probabilistic behavior of RSASSA-PSS.*

## Implementation

The service is implemented in Python 3.11. RESTful API of the service is implemented using the FastAPI
framework.

`ServicePlatform` class from [server_platform.py](app/server_platform.py) contains `signWithKey` and
`makeRequest` methods, which correspond to `POST /sign` and `POST /makeRequest` API endpoints.

Cryptographic operations (necessary for implementation of the `POST /sign` endpoint) use
[cryptography](https://cryptography.io/) library (which itself depends on the OpenSSL C library).

Making HTTP request (for the `POST /makeRequest` endpoint) is done with the Python's standard `urllib`
library.

Certificates and their private keys used for making mTLS connections and cryptographic signing are
read from the file system, which can be changed if necessary by changing corresponding functionality
in the `ServicePlatform` class.

Implementation of secured access to the service (using client TLS certificate verification) relies on
[nginx](https://nginx.org/). Please refer to [nginx.conf](nginx.conf). *Please notice that this
configuration uses port 80 for secured connections.*

### Running service locally without Docker

Setting up environment:

```
pyenv install 3.11.1
pyenv virtualenv 3.11.1 open-banking-eidas-broker-3.11.1
pyenv activate open-banking-eidas-broker-3.11.1
pip install -r requirements.txt
```

Running the service:

```
gunicorn app.main:app -c gunicorn_conf.py -k uvicorn.workers.UvicornWorker --bind=:8888 --chdir=app
```

--

Copyright 2021 Enable Banking Oy
