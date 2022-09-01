FROM nginx:1.23.1

RUN apt update && apt upgrade -y
RUN apt install python3 python3-pip -y
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY ./app /app
COPY certs/server/* /app/broker_tls/
COPY gunicorn_conf.py /gunicorn_conf.py

COPY run.sh .
RUN chmod +x run.sh
COPY nginx.conf /etc/nginx/conf.d/default.conf

# ENTRYPOINT gunicorn app.main:app -c /gunicorn_conf.py -k uvicorn.workers.UvicornWorker --bind=unix:server.sock --chdir=/app
ENTRYPOINT ./run.sh
