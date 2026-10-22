"""Request models (pydantic)."""
from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class RepoCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    description: str = Field(default="", max_length=300)


class ReviewRequest(BaseModel):
    status: Literal["accepted", "rejected", "fixed", "disputed", "open"]
    comment: str = Field(default="", max_length=1000)


class QuestionRequest(BaseModel):
    repo_id: int
    question: str = Field(min_length=3, max_length=1000)


class LogRequest(BaseModel):
    repo_id: int
    name: str = Field(default="build.log", max_length=120)
    content: str = Field(min_length=1, max_length=2_000_000)


class FileWrite(BaseModel):
    path: str = Field(min_length=1, max_length=260)
    content: str = Field(max_length=2_000_000)
