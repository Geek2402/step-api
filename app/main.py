import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import AppError

logger = logging.getLogger("step")

app = FastAPI(title=settings.PROJECT_NAME, docs_url=None, redoc_url=None)

if settings.ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router, prefix=settings.API_V1_PREFIX)

# Static assets (e.g. the logo embedded in transactional emails, referenced by
# absolute URL since email clients cannot resolve relative paths or bundled assets).
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ---------- Global error handling ----------

@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request: Request, exc: IntegrityError):
    # Safety net for race conditions (e.g. two simultaneous sign-ups
    # with the same email) that slip between the check SELECT and the INSERT.
    logger.warning("Integrity constraint violated on %s: %s", request.url.path, exc)
    return JSONResponse(status_code=409, content={"detail": "Data conflict (likely duplicate)"})


@app.exception_handler(RedisError)
async def redis_error_handler(request: Request, exc: RedisError):
    logger.error("Redis error on %s: %s", request.url.path, exc)
    return JSONResponse(status_code=503, content={"detail": "Service temporarily unavailable, please try again"})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


PUBLIC_TAGS = {"end-user-auth", "end-users"}


def _collect_schema_refs(node) -> set[str]:
    """Recursively collects component schema names referenced (directly or via
    nested $ref) anywhere within the given OpenAPI fragment."""
    refs: set[str] = set()
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            refs.add(ref.removeprefix("#/components/schemas/"))
        for value in node.values():
            refs |= _collect_schema_refs(value)
    elif isinstance(node, list):
        for item in node:
            refs |= _collect_schema_refs(item)
    return refs


def _end_user_openapi() -> dict:
    """Public docs: end-user-auth (login/OTP) and end-users (CRUD) routes, given to integrating developers."""
    schema = get_openapi(title="Step — End-Users API", version="1.0.0", routes=app.routes)
    schema["paths"] = {
        path: methods
        for path, methods in schema["paths"].items()
        if any(PUBLIC_TAGS & set(op.get("tags", [])) for op in methods.values())
    }

    all_schemas = schema.get("components", {}).get("schemas", {})
    used = _collect_schema_refs(schema["paths"])
    # Transitive closure: a referenced schema can itself reference other schemas.
    frontier = set(used)
    while frontier:
        frontier = _collect_schema_refs({name: all_schemas[name] for name in frontier if name in all_schemas}) - used
        used |= frontier

    if "components" in schema and "schemas" in schema["components"]:
        schema["components"]["schemas"] = {
            name: definition for name, definition in all_schemas.items() if name in used
        }

    return schema


def _admin_openapi() -> dict:
    """Full docs, internal use only."""
    return get_openapi(title="Step — Full API (admin)", version="1.0.0", routes=app.routes)


@app.get("/openapi-public.json", include_in_schema=False)
async def openapi_public():
    return JSONResponse(_end_user_openapi())


@app.get("/openapi-admin.json", include_in_schema=False)
async def openapi_admin():
    return JSONResponse(_admin_openapi())


@app.get("/docs", include_in_schema=False)
async def public_docs():
    return get_swagger_ui_html(openapi_url="/openapi-public.json", title="Step — End-Users API")


@app.get("/docs/admin", include_in_schema=False)
async def admin_docs():
    return get_swagger_ui_html(openapi_url="/openapi-admin.json", title="Step — Admin API")


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok"}
