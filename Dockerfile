FROM python:3.11.1-slim-bullseye

RUN apt update && apt upgrade -y
RUN apt install nginx -y

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY ./app /app
COPY certs/server/* /app/broker_tls/

COPY run.sh .
COPY run.py .
RUN chmod +x run.sh
COPY nginx.conf /etc/nginx/sites-available/default

ENTRYPOINT ./run.sh
