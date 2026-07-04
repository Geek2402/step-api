from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.config import settings

app = FastAPI(title=settings.PROJECT_NAME, docs_url=None, redoc_url=None)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


def _end_user_openapi() -> dict:
    """Doc publique : uniquement les routes taguées end-user-auth, donnée aux développeurs."""
    schema = get_openapi(title="Step — API End-Users", version="1.0.0", routes=app.routes)
    schema["paths"] = {
        path: methods
        for path, methods in schema["paths"].items()
        if any("end-user-auth" in op.get("tags", []) for op in methods.values())
    }
    return schema


def _admin_openapi() -> dict:
    """Doc complète, usage interne uniquement."""
    return get_openapi(title="Step — API complète (admin)", version="1.0.0", routes=app.routes)


@app.get("/openapi-public.json", include_in_schema=False)
async def openapi_public():
    return JSONResponse(_end_user_openapi())


@app.get("/openapi-admin.json", include_in_schema=False)
async def openapi_admin():
    return JSONResponse(_admin_openapi())


@app.get("/docs", include_in_schema=False)
async def public_docs():
    return get_swagger_ui_html(openapi_url="/openapi-public.json", title="Step — API End-Users")


@app.get("/docs/admin", include_in_schema=False)
async def admin_docs():
    return get_swagger_ui_html(openapi_url="/openapi-admin.json", title="Step — API Admin")


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok"}
