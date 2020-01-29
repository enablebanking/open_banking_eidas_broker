# CA
Create CA key and certificate for signing server (and client) certificates<br/>
`openssl genrsa -out ca.key 4096`<br/>
Replace values under `-subj` parameter by appropriate (if necessary)<br/>
`openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleOrganisation/CN=www.bigorg.com"`

# Server
`openssl genrsa -out server.key 4096`<br/>
Make sure the `CN` parameter matches the location of you host<br/>
`openssl req -new -key server.key -out server.csr -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleServerOrganisation/CN=localhost"`<br/>
Signing server certificate with ca.key. It is mandatory not to use md5 message digest. That's why we use sha256<br/>
`openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -sha256`


# Client (if necessary)
`openssl genrsa -out client.key 4096`<br/>
`openssl req -new -key client.key -out client.csr  -subj "/C=FI/ST=Uusima/L=Helsinki/O=ExampleClientOrganisation/CN=www.localorg.com"`<br/>
Signing client certificate with ca.key<br/>
`openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt -sha256`<br/>

# Verifying (optional)
Varify server and client certifiactes<br/>
`openssl verify -purpose sslserver -CAfile ca.crt server.crt`<br/>
`openssl verify -purpose sslclient -CAfile ca.crt client.crt`<br/>
