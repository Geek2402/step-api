from fastapi import APIRouter

from app.api.v1 import admin, apps, end_users_auth, users_auth

api_router = APIRouter()
api_router.include_router(users_auth.router)
api_router.include_router(apps.router)
api_router.include_router(end_users_auth.router)
api_router.include_router(admin.router)
