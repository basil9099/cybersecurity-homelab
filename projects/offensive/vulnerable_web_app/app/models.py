"""Pydantic models for request/response validation."""

from pydantic import BaseModel


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response model."""
    success: bool
    message: str
    token: str | None = None
    user: dict | None = None


class SearchRequest(BaseModel):
    """Search request model."""
    query: str


class GuestbookEntry(BaseModel):
    """Guestbook entry model."""
    author: str
    content: str


class FlagSubmission(BaseModel):
    """Flag submission model."""
    challenge: str
    flag: str


class FlagResponse(BaseModel):
    """Flag validation response."""
    correct: bool
    message: str


class CommandRequest(BaseModel):
    """Command request model for ping endpoint."""
    target: str


class URLFetchRequest(BaseModel):
    """URL fetch request model for SSRF endpoint."""
    url: str


class XMLData(BaseModel):
    """XML data model for XXE endpoint."""
    xml_content: str


class ProfileResponse(BaseModel):
    """User profile response."""
    id: int
    username: str
    email: str
    role: str
    secret_note: str


class HintRequest(BaseModel):
    """Hint request model."""
    challenge: str
    level: int = 1
