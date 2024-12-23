FROM python:3.13-slim


# nginx pre-requisites
RUN apt update && apt upgrade -y

RUN apt install curl gnupg2 ca-certificates lsb-release debian-archive-keyring -y
RUN curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
RUN echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/debian `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
RUN echo "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | tee /etc/apt/preferences.d/99nginx

RUN apt update
RUN apt install nginx ca-certificates -y

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
