cd /app
uvicorn main:app --uds=server.sock &
nginx -g "daemon off;"
