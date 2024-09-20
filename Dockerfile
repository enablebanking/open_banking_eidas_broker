FROM python:3.11.1-slim-bullseye

RUN apt update && apt upgrade -y
RUN apt install -y nginx ca-certificates

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --upgrade setuptools
RUN pip install -r requirements.txt
COPY ./app /app

# adding trusted banks' self-signed certificates to the trust store
COPY trusted_aspsps_certs/ /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

COPY run.sh .
COPY run.py .
RUN chmod +x run.sh
COPY nginx.conf /etc/nginx/sites-available/default

ENTRYPOINT ["sh", "run.sh"]
