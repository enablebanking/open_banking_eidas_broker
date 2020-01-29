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
If you want to generate self-signed certificates, see [how to create self-signed certificates](GENERATING_CERTIFICATES.md)
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

# Check available endpoints
Container endpoints documentation is available at `/docs` or `/redoc`:<br/>
`http://localhost:<host_port>/docs`<br/>
`http://localhost:<host_port>/redoc`
