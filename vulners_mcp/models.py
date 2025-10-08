from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---- Search ----
class LuceneSearchRequest(BaseModel):
    query: str
    skip: int | None = Field(default=0, ge=0)
    size: int | None = Field(default=20, ge=1, le=500)
    fields: list[str] | None = None


class BulletinPreview(BaseModel):
    id: str | None = None
    title: str | None = None
    type: str | None = None
    href: str | None = None
    published: str | None = None
    modified: str | None = None
    cvelist: list[str] | None = None
    short_description: str | None = None
    model_config = ConfigDict(extra="allow")


class LuceneSearchResponse(BaseModel):
    total: int | None = None
    skip: int | None = None
    size: int | None = None
    results: list[BulletinPreview] = Field(default_factory=list)


class CvssScore(BaseModel):
    score: float | None = None
    severity: str | None = None
    vector: str | None = None


class WindowsAuditBulletin(BaseModel):
    package: str | None = None
    published: str | None = None
    bulletinID: str | None = None
    cvelist: list[str] = Field(default_factory=list)
    cvss: CvssScore | None = None
    fix: str | None = None


class LinuxPackageFinding(BaseModel):
    package: str | None = None
    bulletinID: str | None = None
    cvelist: list[str] = Field(default_factory=list)
    cvss: CvssScore | None = None
    fix: str | None = None
    model_config = ConfigDict(extra="allow")


class LinuxPackageAuditResponse(BaseModel):
    packages: dict[str, dict[str, list[LinuxPackageFinding]]] = Field(
        default_factory=dict
    )
    vulnerabilities: list[str] = Field(default_factory=list)
    cvelist: list[str] = Field(default_factory=list)
    cumulativeFix: str | None = None
    id: str | None = None


class IdSearchRequest(BaseModel):
    id: str | list[str]
    references: bool | None = None
    fields: list[str] | None = None


class BulletinFull(BaseModel):
    id: str | None = None
    model_config = ConfigDict(extra="allow")


IdSearchResponse = BulletinFull | dict[str, BulletinFull]


# ---- Audit ----
class CpeObject(BaseModel):
    part: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    update: str | None = None
    language: str | None = None
    target_hw: str | None = None
    target_sw: str | None = None
    edition: str | None = None


SoftwareItem = str | CpeObject


class AuditSoftwareRequest(BaseModel):
    software: list[SoftwareItem]
    match: str | None = Field(default="partial")  # partial|full
    fields: list[str] | None = None


class Vulnerability(BaseModel):
    id: str | None = None
    title: str | None = None
    short_description: str | None = None
    model_config = ConfigDict(extra="allow")


class AuditResult(BaseModel):
    input: dict[str, Any] | Any
    matched_criteria: str | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class WindowsKbAuditRequest(BaseModel):
    os: str
    kbList: list[str]


class WindowsWinAuditSoftwareEntry(BaseModel):
    software: str
    version: str | None = None
    sw_edition: str | None = None
    target_sw: str | None = None
    target_hw: str | None = None
    update: str | None = None
    language: str | None = None


class WindowsWinAuditRequest(BaseModel):
    os: str
    os_version: str
    kbList: list[str]
    software: list[WindowsWinAuditSoftwareEntry]
    platform: str | None = None


class LinuxPackageAuditRequest(BaseModel):
    os: str
    version: str
    package: list[str]
    include_candidates: bool | None = None


# ---- Basics / Collections ----
class AutocompleteRequest(BaseModel):
    query: str


class CpeSearchResponse(BaseModel):
    best_match: str | None = None
    cpe: list[str] = Field(default_factory=list)


class AutocompleteResponse(list[str]):
    pass


class CollectionEntry(BaseModel):
    id: str | None = None
    timestamps_updated: str | None = Field(None, alias="timestamps.updated")
    model_config = ConfigDict(extra="allow")


class CollectionResponse(list[CollectionEntry]):
    pass


class ErrorResponse(BaseModel):
    code: str
    message: str
