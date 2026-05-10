from contextlib import asynccontextmanager

from fastapi import FastAPI
from app.api.routes import router
from app.core.config import settings
from app.core.logging import setup_logging
from app.storage.audit_store import close_audit_store, init_audit_store

setup_logging()

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_audit_store()
    try:
        yield
    finally:
        close_audit_store()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(router, prefix=settings.api_prefix)


@app.get("/health")
def health():
    return {"status": "ok"}
