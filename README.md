| CAUTION: This project may not suite production use and is mainly intended for testing! |
| -------------------------------------------------------------------------------------- |

# Open Banking eIDAS broker

The broker service provides possibility to use eIDAS certificates *(in practice any X.509 certificates)* for generating signatures and sending HTTP requests over mTLS connections without need to expose private keys of the certificates with the service client.

The web API of the broker service consists of 2 endpoints:

1. `/sign` -- for signing received data with a QSeal certificate and returning this signature back;
2. `/make-request` -- for making HTTP request over mutual TLS connection established with a QWAC certificate and returning response back.

Access to the broker service APIs is provided over mTLS and authentication of the client is done based on the client certificate. The client certificate and the broker server certificate shall be signed using the same CA certificate.

## Accessing ASPSP APIs through eIDAS broker

The flow of the calls between client, broker service and ASPSP looks like this:

```
   [Client premises]            --   [Broker service holding eIDAS keys]   --   [Open banking API (ASPSP)]

1. OB API request to be signed  ->   Signing the data using a QSeal
                                     certificate named by the client
   Request signature            <-   and returning the signature

                                     Forwarding the request to an ASPSP 
2. OB API request to be sent    ->   over mTLS established with a QWAC     ->   ASPSP gets complete API
                                     certificate named by the client            request, verifies the
                                                                                signature, and responses
   Response from the ASPSP      <-   Returning the response back to the    <-   to the broker service
                                     initiating party
```

The client may request to use different certificates (identified by URI) and to forward arbitrary requests (to different ASPSPs).

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


### Client

`openssl genrsa -out client.key 4096`<br/>
`openssl req -new -key client.key -out client.csr  -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleClientOrganisation/CN=www.localorg.com"`<br/>
Signing client certificate with ca.key<br/>
`openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt -sha256`<br/>


## Verifying (optional)

Verify server and client certifiactes<br/>
`openssl verify -purpose sslserver -CAfile ca.crt server.crt`<br/>
`openssl verify -purpose sslclient -CAfile ca.crt client.crt`<br/>


Copyright 2020 Enable Banking Oy
