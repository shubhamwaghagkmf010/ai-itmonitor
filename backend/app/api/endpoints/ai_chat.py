from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.api.deps import get_current_user
from backend.app.models.entities import User
from backend.app.ai.chat_service import query_ai_assistant

router = APIRouter()


class ChatQueryRequest(BaseModel):
    message: str
    machine_context: Optional[dict] = None


class ChatQueryResponse(BaseModel):
    reply: str


@router.post("/chat", response_model=ChatQueryResponse)
def handle_chat_query(
    payload: ChatQueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Answers user queries grounded in real-time infrastructure data."""
    answer = query_ai_assistant(payload.message, db, payload.machine_context)
    return {"reply": answer}
