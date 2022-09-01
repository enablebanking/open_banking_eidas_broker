gunicorn app.main:app -c /gunicorn_conf.py -k uvicorn.workers.UvicornWorker --bind=unix:server.sock --chdir=/app &
nginx -g "daemon off;"
