Prerequisites:
- Have python 3.12 installed (earlier versions are likely to work as well)
- Have pip installed

Install dependencies:  
`pip install -r tests/requirements`

Setup following environment variables:  
BROKER_ORIGIN – origin/url of your broker  
QSEAL_CERT_PATH – path to public QSeal certificate   
QSEAL_KEY_NAME – name of a private key inside the broker
MTLS_CLIENT_CERT_PATH - path to client MTLS certificate  
MTLS_CLIENT_KEY_PATH - path to client MTLS private key  

Optionally you can modify:  
MOCK_ORIGIN – Origin to a server which is intended to be called by the broker. Default is https://eidas-mock-todjdqftaa-ez.a.run.app

To run tests:
`pytest tests`
