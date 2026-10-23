from typing import Optional
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user
from backend.app.models.entities import User
from backend.app.ai.chat_service import stream_ai_assistant

router = APIRouter()


class ChatQueryRequest(BaseModel):
    message: str
    machine_context: Optional[dict] = None


@router.post("/chat")
def handle_chat_query(
    payload: ChatQueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Streams the AI SRE Copilot's answer back as plain text, token-by-token, so
    the reply starts appearing immediately instead of waiting for the whole thing."""
    return StreamingResponse(
        stream_ai_assistant(payload.message, db, payload.machine_context),
        media_type="text/plain; charset=utf-8",
    )
