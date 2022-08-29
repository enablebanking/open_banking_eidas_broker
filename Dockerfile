FROM tiangolo/uvicorn-gunicorn-fastapi:python3.7

RUN pip install cryptography==2.6.1
COPY ./app /app
COPY gunicorn_conf.py /gunicorn_conf.py
