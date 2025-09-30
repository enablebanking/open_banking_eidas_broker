FROM python:3.13.6-slim


RUN apt update && apt upgrade -y
RUN apt install nginx ca-certificates -y

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --upgrade setuptools
RUN pip install -r requirements.txt
COPY ./app /app

# adding trusted banks' self-signed certificates to the trust store
COPY trusted_aspsps_certs/ /usr/local/share/ca-certificates/trusted_aspsps_certs/
RUN cat $(python -m certifi) /usr/local/share/ca-certificates/trusted_aspsps_certs/* > /etc/ssl/certs/eidas-broker-ca-bundle.pem
ENV SSL_CERT_FILE=/etc/ssl/certs/eidas-broker-ca-bundle.pem

COPY run.sh .
COPY run.py .
RUN chmod +x run.sh
COPY nginx.conf /etc/nginx/sites-available/default

ENTRYPOINT ["sh", "run.sh"]
