from __future__ import annotations

from typing import Any, Literal

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
# The body models below are closed (every field declared) so tool input
# schemas stay usable in OpenAI strict mode, which rejects free-form objects.
# Unknown keys are still ignored rather than rejected: older tool docs told
# models to send a `platform` field that /api/v4/audit/software never had.
# VU-2404.
_ANY = 'use "*" for any'


class CpeObject(BaseModel):
    """CPE 2.3 well-formed name, one field per WFN attribute."""

    part: str | None = Field(
        default=None, description='"a" application, "o" operating system, "h" hardware'
    )
    vendor: str = Field(description="Vendor, e.g. openssl, google, microsoft")
    product: str = Field(description="Product, e.g. openssl, chrome, edge")
    version: str = Field(description="Exact version, e.g. 1.1.1u or 138.0.7204.184")
    update: str | None = Field(default=None, description=f"Update; {_ANY}")
    edition: str | None = Field(default=None, description=f"Edition; {_ANY}")
    language: str | None = Field(default=None, description=f"Language; {_ANY}")
    sw_edition: str | None = Field(
        default=None, description=f"Software edition; {_ANY}"
    )
    target_sw: str | None = Field(
        default=None,
        description=f'Target software, e.g. "windows" or "macos"; {_ANY}',
    )
    target_hw: str | None = Field(default=None, description=f"Target hardware; {_ANY}")
    other: str | None = Field(default=None, description=f"Other; {_ANY}")


SoftwareItem = CpeObject | str


class AuditSoftwareRequest(BaseModel):
    software: list[SoftwareItem] = Field(
        description="Software to audit: structured CPE objects (preferred) or CPE 2.3 strings"
    )
    match: Literal["partial", "full"] | None = Field(
        default=None,
        description='"partial" (API default) or "full"; use "full" with target_sw for OS-specific audits',
    )


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


# ---- Basics / Collections ----
class AutocompleteRequest(BaseModel):
    query: str = Field(
        description="Partial search term, e.g. 'openssl', 'CVE-2024-', 'microsoft windows'"
    )


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
