# Building an image and starting a container
In order to build an image you need to:
1. Have docker installed
2. Put you certificates (if your API requires those) into `open_banking_tls/` directory under following names:
    - `public.crt`  # tls public certificate
    - `private.key`  # tls private key
3. Put proxy certificates into `proxy_tls/` directory under following names:
    - `server.key`  # private server (proxy) certificate
    - `server.crt`  # public server (proxy) key
    - `ca.crt`  # public certificate authority certificate
If you want to generate self-signed certificates, see instructions below
5. Put signature certificates into `signature_certs/` directory. You can put certificates under this dirrectory in an arbitrary order. Later these certificates are going to be accessed by path (A.K.A. `key_id`) from the request.
4. Go to the directory with `Dockerfile`
5. Run `docker build -t <image_name> .` (probably you need to prepend this command with `sudo`)<br/>
6. Start built image:<br/>
```
docker run -d \
    --name <container_name> \
    -p 443:80 \
    --mount type=bind,source="$(pwd)"/open_banking_tls/,target=/app/open_banking_tls/ \
    --mount type=bind,source="$(pwd)"/signature_certs/,target=/app/signature_certs/ \
    <image_name>
```

5. Go to `http(s)://localhost:<host_port>` to verify that everything works (you will need to provide proxy certificates with you requirest in order to see the page)

## Check available endpoints
Container endpoints documentation is available at `/docs` or `/redoc`:<br/>
`http(s)://localhost:<host_port>/docs`<br/>
`http(s)://localhost:<host_port>/redoc`


# Certificates
## CA
Create CA key and certificate for signing server (and client) certificates<br/>
`openssl genrsa -out ca.key 4096`<br/>
Replace values under `-subj` parameter by appropriate (if necessary)<br/>
`openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleOrganisation/CN=www.bigorg.com"`

## Server
`openssl genrsa -out server.key 4096`<br/>
Make sure the `CN` parameter matches the location of you host<br/>
`openssl req -new -key server.key -out server.csr -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleServerOrganisation/CN=localhost"`<br/>
Signing server certificate with ca.key. It is mandatory not to use md5 message digest. That's why we use sha256<br/>
`openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -sha256`


## Client (if necessary)
`openssl genrsa -out client.key 4096`<br/>
`openssl req -new -key client.key -out client.csr  -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleClientOrganisation/CN=www.localorg.com"`<br/>
Signing client certificate with ca.key<br/>
`openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt -sha256`<br/>

# Verifying (optional)
Verify server and client certifiactes<br/>
`openssl verify -purpose sslserver -CAfile ca.crt server.crt`<br/>
`openssl verify -purpose sslclient -CAfile ca.crt client.crt`<br/>
