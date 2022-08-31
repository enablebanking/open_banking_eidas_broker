| CAUTION: This project is originally intended for testing, be careful if using in production  |
| -------------------------------------------------------------------------------------------- |

# Open Banking eIDAS broker

The broker service provides possibility to use eIDAS certificates *(in practice any X.509
certificates)* for generating signatures and sending HTTP requests over mTLS connections
without need to expose private keys of the certificates with the service client.

The web API of the broker service consists of 3 endpoints:

1. `/sign` -- for signing received data with a QSeal certificate and returning this
   signature back;
2. `/makeRequest` -- for making HTTP request over mutual TLS connection established with
   a QWAC certificate and returning response back.
3. `/health` -- for health checks to make sure that application is up and running.

Access to the broker service APIs is provided over mTLS and authentication of the client is
done based on the client certificate. The client certificate and the broker server certificate
shall be signed using the same CA certificate.

The broker service is primarily designed to be called from [enable:Banking aggregation
SDK](https://enablebanking.com/docs/sdk/latest/), which provides special `BrokerPlatform`
class offloading signing and mTLS funtionality to the broker. 

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
    -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleOrganisation/CN=www.bigorg.com"
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
    -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleServerOrganisation/CN=localhost"
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

And client CSR is generated the same way how it's done for the server.

```bash
openssl req -new -key client.key -out client.csr \
    -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleClientOrganisation/CN=www.localorg.com"
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
2. Put broker certificates you generated earlier into `server_certs/` directory under following names:
    - `server.key`  # private key of the server (broker) certificate
    - `server.crt`  # public server (broker) certificate
    - `ca.crt`  # public CA certificate
3. Go to the directory with `Dockerfile`
4. Run `docker build -t <image_name> .` (probably you need to prepend this command with `sudo`)<br/>
5. Put you QWAC (mTLS) and QSealC (signature) certificates into `open_banking_certs/` directory, which will be mounted to the container.<br/>
You can put certificates in an arbitrary order/names. Later you will have to provide paths to those certificates.<br/>
All certificates must be in the PEM format.</br>
    - `qwac.key`  # QWAC private key. Needed for establishing mTLS
    - `qwac.crt`  # QWAC public certificate. Needed for establishing mTLS
    - `qwac_chain.crt` (optional)  # QWAC certificate chain. Some banks require it
    - `qseal.key`  # QSeal private key. Used for creating signatures
6. Start built image:  

```
docker run -d \
    --name <container_name> \
    -p 443:80 \
    --mount type=bind,source="$(pwd)"/open_banking_certs/,target=/app/open_banking_certs/ \  
    --mount type=bind,source="$(pwd)"/server_certs/,target=/app/broker_tls/ \
    <image_name>
```  

You can also specify `verify_cert` environment variable using `-e` flag if you want you requests to banks to be verified against QWAC certificate chain (if it is provided).

7. Go to `http(s)://localhost:<host_port>` to verify that everything works (you will need to provide broker certificates with you request in order to see the page)

## Check available endpoints
Container endpoints documentation is available at `/docs` or `/redoc`:<br/>
`http(s)://localhost:<host_port>/docs`<br/>
`http(s)://localhost:<host_port>/redoc`


Copyright 2021 Enable Banking Oy
