FROM tiangolo/uvicorn-gunicorn-fastapi:python3.7

RUN pip install cryptography==37.0.4
COPY ./app /app
COPY gunicorn_conf.py /gunicorn_conf.py
