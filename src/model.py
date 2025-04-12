from pydantic import BaseModel
from typing import List
from typing import Literal


class Span(BaseModel):
    start: int
    end: int


class Vulnerability(BaseModel):
    code: str
    cwe: List[str]
    span: Span
    falsePositive: bool
    language: str
