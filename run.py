import multiprocessing
import uvicorn

if __name__ == "__main__":
    workers = multiprocessing.cpu_count() * 2 + 1
    uvicorn.run("main:app", uds="server.sock", workers=workers, app_dir="app")
