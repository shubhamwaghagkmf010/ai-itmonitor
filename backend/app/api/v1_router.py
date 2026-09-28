from fastapi import APIRouter
from backend.app.api.endpoints import auth, agents, incidents, ai_chat, admin, wol, network, assets

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(agents.router, prefix="/agents", tags=["agents"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(ai_chat.router, prefix="/ai", tags=["ai"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(wol.router, prefix="/wol", tags=["wol"])
api_router.include_router(network.router, prefix="/network", tags=["network"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
