"""
CloudSentinel  - Backend (FastAPI)

تشغيل:
    uvicorn main:app --reload
بعدها افتح:
    http://127.0.0.1:8000/docs   (صفحة تجربة الـ API جاهزة)
"""

import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from cfn.compare import compare_scans
from cfn.loader import load_template_text
from cfn.parser import TemplateError
from cfn.rules import RULES
from cfn.samples import CFN_SAMPLES
from cfn.scanner import scan_template
from samples import SAMPLE_ENVIRONMENTS
from scanner import scan

app = FastAPI(title="CloudSentinel ", version="0.1.0")

# الـ API عام على النت، فبنرفض أي request أكبر من الحد ده (الـ frontend أصلًا بيمنع أكتر من 1MB للملف)
MAX_BODY_BYTES = 3_000_000


@app.middleware("http")
async def limit_body_size(request, call_next):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "Request body too large"}, status_code=413)
    return await call_next(request)


# الـ Frontend المنشور: حط عنوانه في متغير البيئة ALLOWED_ORIGINS (ممكن أكتر من عنوان بينهم فاصلة)
# مثال: ALLOWED_ORIGINS=https://cloudsentinel.pages.dev
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]

# بيتضاف بعد الـ middleware اللي فوق عشان يبقى الأخير (الأبعد)، فرد 413 كمان بيرجع بـ CORS headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",  # للتطوير المحلي: أي بورت على جهازك
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    config: dict


class TemplateRequest(BaseModel):
    template: Optional[dict] = None       # JSON template as an object
    template_text: Optional[str] = None   # JSON or YAML template as raw text


class CompareRequest(BaseModel):
    before: Optional[dict] = None
    after: Optional[dict] = None
    before_text: Optional[str] = None
    after_text: Optional[str] = None


def _resolve(obj: Optional[dict], text: Optional[str], label: str) -> dict:
    """Return the template as a dict from either an object or raw JSON/YAML text (exactly one must be given)."""
    if (obj is None) == (text is None):
        raise HTTPException(status_code=422, detail=f"Provide exactly one of '{label}' or '{label}_text'.")
    if obj is not None:
        return obj
    try:
        return load_template_text(text)
    except TemplateError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def _scan_or_422(template: dict) -> dict:
    try:
        return scan_template(template)
    except TemplateError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/")
def home():
    return {"message": "CloudSentinel is running"}


@app.get("/api/samples")
def list_samples():
    """قايمة البيئات التجريبية (من غير الـ config نفسه)."""
    return [
        {"id": key, "label": env["label"], "description": env["description"]}
        for key, env in SAMPLE_ENVIRONMENTS.items()
    ]


@app.get("/api/samples/{sample_id}")
def get_sample(sample_id: str):
    env = SAMPLE_ENVIRONMENTS.get(sample_id)
    if env is None:
        raise HTTPException(status_code=404, detail="Sample environment not found")
    return {"id": sample_id, "label": env["label"], "config": env["config"]}


@app.post("/api/scan/sample/{sample_id}")
def scan_sample(sample_id: str):
    env = SAMPLE_ENVIRONMENTS.get(sample_id)
    if env is None:
        raise HTTPException(status_code=404, detail="Sample environment not found")
    return scan(env["config"])


@app.post("/api/scan")
def scan_config(request: ScanRequest):
    """فحص config مرفوع من المستخدم (JSON)."""
    return scan(request.config)


# ------------------------------------------------ CloudFormation (v2) API
# الـ endpoints القديمة (/api/scan, /api/samples) فوق لسه شغالة زي ما هي.


@app.get("/api/cfn/rules")
def cfn_rules():
    """كتالوج القواعد: كل قاعدة بتفحص إيه وليه."""
    return [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "applies_to": r.applies_to,
            "impact": r.impact,
            "recommendation": r.recommendation,
            "reference": r.reference,
        }
        for r in RULES
    ]


@app.get("/api/cfn/samples")
def cfn_list_samples():
    return [
        {"id": key, "label": s["label"], "description": s["description"]}
        for key, s in CFN_SAMPLES.items()
    ]


@app.get("/api/cfn/samples/{sample_id}")
def cfn_get_sample(sample_id: str):
    sample = CFN_SAMPLES.get(sample_id)
    if sample is None:
        raise HTTPException(status_code=404, detail="Sample template not found")
    return {"id": sample_id, "label": sample["label"], "template": sample["template"]}


@app.post("/api/cfn/scan/sample/{sample_id}")
def cfn_scan_sample(sample_id: str):
    sample = CFN_SAMPLES.get(sample_id)
    if sample is None:
        raise HTTPException(status_code=404, detail="Sample template not found")
    return _scan_or_422(sample["template"])


@app.post("/api/cfn/scan")
def cfn_scan(request: TemplateRequest):
    """فحص CloudFormation template (JSON أو YAML) مرفوع من المستخدم."""
    return _scan_or_422(_resolve(request.template, request.template_text, "template"))


@app.post("/api/cfn/compare")
def cfn_compare(request: CompareRequest):
    """مقارنة فحصين: قبل وبعد التعديل."""
    before = _resolve(request.before, request.before_text, "before")
    after = _resolve(request.after, request.after_text, "after")
    return compare_scans(_scan_or_422(before), _scan_or_422(after))
