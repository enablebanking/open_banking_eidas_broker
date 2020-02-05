| WARNING: This project is not production-ready and intended only for testing purposes! |
| --- |

# Open Banking eIDAS broker

This project is intended to be used in situations where you need to test an API, which requires usage of QSeal private key and/or TLS cert/key pair, but these certificates is only accessible from a remote server.

The docker image has 2 endpoints:

1. For signing received data with private QSeal certificate and returning this signature back
2. For signing received HTTP request with TLS cert/key pair, forwarding signed request to the API, receiving a response from API and returning it back to the initiating party.

In other words, the flow looks like this:<br/>
```
   [Local premises]   --   [Remote cerver with certificates]   --   [API]

1. Some_data          ->   Receiving and signing the data
   Data_signature     <-   with QSeal certificate


                           Receiving the request, signing it        API gets the request
2. HTTP_request      ->    with TLS cert/key pair and          ->   and returns response
                           sending it further to an API             to the remote server

   Response from           Remote server just forwards the
   an API             <-   response from an API to the         <-
                           initiating party
```


## Building an image and starting a container

In order to build an image you need to:

1. Have docker installed
2. Put you QWAC (mTLS) and QSeal (signature) certificates (if your API requires those) into `open_banking_certs/` directory.<br/>
You can put certificates in an arbitrary order/names. Later you will have to provide paths to those certificates.<br/>
It is proposed to put certificates in the following order:
- `Bank1`
    - `server.key`
    - `server.crt`
    - `signature.key`
    - `ca_cert.crt` (optional)
- `Bank2`
    - `server.key`
    - `server.crt`
    - `signature.key`
3. Put broker certificates into `broker_tls/` directory under following names:
    - `server.key`  # private server (broker) certificate
    - `server.crt`  # public server (broker) key
    - `ca.crt`  # public certificate authority certificate
If you want to generate self-signed certificates, see instructions below
4. Go to the directory with `Dockerfile`
5. Run `docker build -t <image_name> .` (probably you need to prepend this command with `sudo`)<br/>
6. Start built image:

```
docker run -d \
    --name <container_name> \
    -p 443:80 \
    --mount type=bind,source="$(pwd)"/open_banking_certs/,target=/app/open_banking_certs/ \
    <image_name>
```

You can also specify `verify_cert` environment variable using `-e` flag if you want you requests to banks to be verified against QWAC certificate chain (if it is provided).

7. Go to `http(s)://localhost:<host_port>` to verify that everything works (you will need to provide broker certificates with you requirest in order to see the page)

## Check available endpoints
Container endpoints documentation is available at `/docs` or `/redoc`:<br/>
`http(s)://localhost:<host_port>/docs`<br/>
`http(s)://localhost:<host_port>/redoc`


## Certificates

### CA
Create CA key and certificate for signing server (and client) certificates<br/>
`openssl genrsa -out ca.key 4096`<br/>
Replace values under `-subj` parameter by appropriate (if necessary)<br/>
`openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleOrganisation/CN=www.bigorg.com"`


### Server

`openssl genrsa -out server.key 4096`<br/>
Make sure the `CN` parameter matches the location of you host<br/>
`openssl req -new -key server.key -out server.csr -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleServerOrganisation/CN=localhost"`<br/>
Signing server certificate with ca.key. It is mandatory not to use md5 message digest. That's why we use sha256<br/>
`openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -sha256`


### Client (if necessary)

`openssl genrsa -out client.key 4096`<br/>
`openssl req -new -key client.key -out client.csr  -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleClientOrganisation/CN=www.localorg.com"`<br/>
Signing client certificate with ca.key<br/>
`openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt -sha256`<br/>


## Verifying (optional)

Verify server and client certifiactes<br/>
`openssl verify -purpose sslserver -CAfile ca.crt server.crt`<br/>
`openssl verify -purpose sslclient -CAfile ca.crt client.crt`<br/>


Copyright 2020 Enable Banking Oy
