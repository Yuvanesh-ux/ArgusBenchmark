from pydantic import BaseModel
from typing import List


class Span(BaseModel):
    start: int
    end: int


class Vulnerability(BaseModel):
    code: str
    cwe: str
    span: Span
    falsePositive: bool
    language: str
