from __future__ import annotations
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, RootModel

# ---- Search ----
class LuceneSearchRequest(BaseModel):
    query: str
    skip: int | None = Field(default=0, ge=0)
    size: int | None = Field(default=20, ge=1, le=500)
    fields: Optional[List[str]] = None

class BulletinPreview(BaseModel):
    id: Optional[str] = None
    title: Optional[str] = None
    type: Optional[str] = None
    href: Optional[str] = None
    published: Optional[str] = None
    modified: Optional[str] = None
    cvelist: Optional[List[str]] = None
    short_description: Optional[str] = None
    model_config = {"extra": "allow"}  # allow extra keys

class LuceneSearchResponse(BaseModel):
    total: Optional[int] = None
    skip: Optional[int] = None
    size: Optional[int] = None
    results: List[BulletinPreview] = Field(default_factory=list)

class IdSearchRequest(BaseModel):
    id: Union[str, List[str]]
    references: Optional[bool] = None
    fields: Optional[List[str]] = None

class BulletinFull(BaseModel):
    id: Optional[str] = None
    model_config = {"extra": "allow"}

IdSearchResponse = Union[BulletinFull, Dict[str, BulletinFull]]

# ---- Audit ----
class CpeObject(BaseModel):
    part: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    update: Optional[str] = None
    language: Optional[str] = None
    target_hw: Optional[str] = None
    target_sw: Optional[str] = None
    edition: Optional[str] = None

SoftwareItem = Union[str, CpeObject]

class AuditSoftwareRequest(BaseModel):
    software: List[SoftwareItem]
    match: Optional[str] = Field(default="partial")  # partial|full
    fields: Optional[List[str]] = None

class Vulnerability(BaseModel):
    id: Optional[str] = None
    title: Optional[str] = None
    short_description: Optional[str] = None
    model_config = {"extra": "allow"}

class AuditResult(BaseModel):
    input: Dict[str, Any] | Any
    matched_criteria: Optional[str] = None
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)

class WindowsKbAuditRequest(BaseModel):
    os: str
    kbList: List[str]

class WindowsWinAuditSoftwareEntry(BaseModel):
    software: str
    version: Optional[str] = None
    sw_edition: Optional[str] = None
    target_sw: Optional[str] = None
    target_hw: Optional[str] = None
    update: Optional[str] = None
    language: Optional[str] = None

class WindowsWinAuditRequest(BaseModel):
    os: str
    os_version: str
    kbList: List[str]
    software: List[WindowsWinAuditSoftwareEntry]
    platform: Optional[str] = None

class LinuxPackageAuditRequest(BaseModel):
    os: str
    version: str
    package: List[str]
    include_candidates: Optional[bool] = None

# ---- Basics / Collections ----
class AutocompleteRequest(BaseModel):
    query: str

class CpeSearchResponse(BaseModel):
    best_match: Optional[str] = None
    cpe: List[str] = Field(default_factory=list)

class SupportedOSResponse(BaseModel):
    operating_systems: List[str]

class CollectionEntry(BaseModel):
    id: Optional[str] = None
    model_config = {"extra": "allow"}

class CollectionResponse(BaseModel):
    RootModel: List[CollectionEntry]
