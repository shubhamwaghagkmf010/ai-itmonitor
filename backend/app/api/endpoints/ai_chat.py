import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.ratelimit import SlidingWindowLimiter
from backend.app.api.deps import require_permission
from backend.app.models.entities import User
from backend.app.ai.chat_service import stream_ai_assistant

router = APIRouter()

MAX_MESSAGE_LENGTH = 4000
MAX_CONTEXT_BYTES = 8 * 1024

# Every answer keeps the local model busy for seconds on modest hardware, so one account cannot queue
# them without limit.
_chat_limit = SlidingWindowLimiter(20, 60)


class ChatQueryRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    machine_context: Optional[dict] = None

    @field_validator("machine_context")
    @classmethod
    def _context_must_be_small(cls, value):
        if value is not None and len(json.dumps(value, default=str)) > MAX_CONTEXT_BYTES:
            raise ValueError(f"machine_context is larger than {MAX_CONTEXT_BYTES} bytes")
        return value


@router.post("/chat")
def handle_chat_query(
    payload: ChatQueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("ai_chat.use"))
):
    """Streams the AI SRE Copilot's answer back as plain text, token-by-token, so
    the reply starts appearing immediately instead of waiting for the whole thing."""
    if not _chat_limit.allow(current_user.email):
        raise HTTPException(status_code=429, detail="Too many questions in a short time; wait a moment.")
    return StreamingResponse(
        stream_ai_assistant(payload.message, db, payload.machine_context),
        media_type="text/plain; charset=utf-8",
    )
