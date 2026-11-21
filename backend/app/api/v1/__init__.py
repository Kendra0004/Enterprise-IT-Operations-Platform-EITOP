"""API v1 router aggregation."""

from fastapi import APIRouter

from app.api.v1 import admin, agent, auth, directory, endpoints

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(admin.router)
api_router.include_router(endpoints.router)
api_router.include_router(agent.router)
api_router.include_router(directory.router)

__all__ = ["api_router"]
