import copy
import hashlib
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from starlette.responses import Response
from pydantic import BaseModel, Field
from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline


MODEL_NAME = os.getenv("PII_MODEL_NAME", "openai/privacy-filter")
LOCAL_FILES_ONLY = os.getenv("TRANSFORMERS_LOCAL_FILES_ONLY", "false").lower() == "true"
POLICY_STORAGE = os.getenv("POLICY_STORAGE", "local").lower()
POLICY_LOCAL_DIR = Path(os.getenv("POLICY_LOCAL_DIR", "data/policies"))
POLICY_CACHE_TTL_SECONDS = int(os.getenv("POLICY_CACHE_TTL_SECONDS", "300"))
LOCAL_DEV_CLIENT_ID = "local-dev"
DEFAULT_POLICY: dict[str, Any] = {
    "policy_version": "sapei-policy-v1",
    "label_mappings": [
        {
            "id": "person",
            "name": "Person name",
            "labels": ["PERSON", "NAME", "PER"],
            "replacement": "[PRIVATE_PERSON]",
            "source": "sapei-default",
            "enabled": True,
        },
        {
            "id": "email",
            "name": "Email address",
            "labels": ["EMAIL"],
            "replacement": "[PRIVATE_EMAIL]",
            "source": "sapei-default",
            "enabled": True,
        },
        {
            "id": "phone",
            "name": "Phone number",
            "labels": ["PHONE", "MOBILE", "TEL", "HP", "MSISDN"],
            "replacement": "[PRIVATE_PHONE]",
            "source": "sapei-default",
            "enabled": True,
        },
        {
            "id": "secret",
            "name": "Secret or credential",
            "labels": ["SECRET", "PASSWORD", "PASS", "TOKEN", "API-KEY", "KEY"],
            "replacement": "[SECRET]",
            "source": "sapei-default",
            "enabled": True,
        },
    ],
    "regex_rules": [
        {
            "id": "id-nik-context",
            "name": "Indonesian KTP/NIK with context",
            "pattern": r"\b(?:NIK|KTP|NO\.?\s*KTP|NOMOR\s+KTP)\b\D{0,30}(\d[\d\s.-]{10,24}\d)",
            "replacement": "[PRIVATE_NIK]",
            "capture_group": 1,
            "ignore_case": True,
            "source": "sapei-default",
            "enabled": True,
        },
        {
            "id": "id-nik-digits",
            "name": "Standalone 15-16 digit identity number",
            "pattern": r"(?<!\d)\d{15,16}(?!\d)",
            "replacement": "[PRIVATE_NIK]",
            "capture_group": 0,
            "ignore_case": False,
            "source": "sapei-default",
            "enabled": True,
        },
        {
            "id": "id-phone",
            "name": "Indonesian mobile phone",
            "pattern": r"\b(?:\+?62|0)8[1-9][0-9][\s.-]?[0-9]{3,4}[\s.-]?[0-9]{3,5}\b",
            "replacement": "[PRIVATE_PHONE]",
            "capture_group": 0,
            "ignore_case": False,
            "source": "sapei-default",
            "enabled": True,
        },
        {
            "id": "email-regex",
            "name": "Email address fallback",
            "pattern": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "replacement": "[PRIVATE_EMAIL]",
            "capture_group": 0,
            "ignore_case": True,
            "source": "sapei-default",
            "enabled": True,
        },
    ],
}

logger = logging.getLogger("pii-masker")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

app = FastAPI(
    title="Local PII Masking API",
    description="Microservice lokal untuk menyensor data pribadi memakai transformers.",
    version="1.0.0",
)

@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    origin = request.headers.get("origin", "*")
    request_headers = request.headers.get("access-control-request-headers", "*")

    if request.method == "OPTIONS":
        response = Response(status_code=204)
    else:
        response = await call_next(request)

    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = request_headers
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response


class MaskRequest(BaseModel):
    text: str = Field(..., description="Teks yang akan diproses.")


class MaskResponse(BaseModel):
    masked_text: str


class RegexRuleInput(BaseModel):
    name: str = Field(..., min_length=1)
    pattern: str = Field(..., min_length=1)
    replacement: str = Field(..., min_length=1)
    capture_group: int = 0
    ignore_case: bool = False
    enabled: bool = True


class LabelMappingInput(BaseModel):
    name: str = Field(..., min_length=1)
    labels: list[str] = Field(..., min_length=1)
    replacement: str = Field(..., min_length=1)
    enabled: bool = True


_classifier = None
_model_load_error: str | None = None
_memory_policy_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def get_classifier():
    global _classifier, _model_load_error

    if _classifier is not None:
        return _classifier

    try:
        tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME,
            local_files_only=LOCAL_FILES_ONLY,
        )
        model = AutoModelForTokenClassification.from_pretrained(
            MODEL_NAME,
            local_files_only=LOCAL_FILES_ONLY,
        )
        _classifier = pipeline(
            task="token-classification",
            model=model,
            tokenizer=tokenizer,
            aggregation_strategy="simple",
        )
        _model_load_error = None
        return _classifier
    except Exception as exc:
        _model_load_error = str(exc)
        logger.exception("Failed to load model %s", MODEL_NAME)
        raise


@app.on_event("startup")
def load_model_on_startup() -> None:
    try:
        get_classifier()
    except Exception:
        logger.warning("Model is not ready. Requests will return 503 until it can be loaded.")


def sanitize_client_id(client_id: str | None) -> str:
    if not client_id:
        return LOCAL_DEV_CLIENT_ID

    clean_client_id = client_id.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", clean_client_id):
        raise HTTPException(status_code=400, detail="X-SAPEI-Client-Id tidak valid.")

    return clean_client_id


def get_client_id(request: Request) -> str:
    return sanitize_client_id(request.headers.get("x-sapei-client-id"))


def policy_local_path(client_id: str) -> Path:
    digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()
    return POLICY_LOCAL_DIR / digest[:2] / digest[2:4] / f"{client_id}.json"


def merge_policy(stored_policy: dict[str, Any] | None, client_id: str) -> dict[str, Any]:
    policy = copy.deepcopy(DEFAULT_POLICY)
    policy["client_id"] = client_id
    policy["storage"] = POLICY_STORAGE

    if not stored_policy:
        return policy

    if isinstance(stored_policy, dict):
        policy.update({key: value for key, value in stored_policy.items() if value is not None})
        policy["client_id"] = client_id

    return policy


def load_policy_from_storage(client_id: str) -> dict[str, Any] | None:
    path = policy_local_path(client_id)
    if not path.exists():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("Failed to load policy file %s", path)
        return None


def save_policy_to_storage(client_id: str, policy: dict[str, Any]) -> None:
    payload = json.dumps(policy, indent=2, ensure_ascii=False) + "\n"

    path = policy_local_path(client_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def load_policy(client_id: str = LOCAL_DEV_CLIENT_ID) -> dict[str, Any]:
    now = time.time()
    cached = _memory_policy_cache.get(client_id)
    if cached and cached[0] > now:
        return copy.deepcopy(cached[1])

    stored_policy = load_policy_from_storage(client_id)
    policy = merge_policy(stored_policy, client_id)
    set_policy_cache(client_id, policy)
    return copy.deepcopy(policy)


def set_policy_cache(client_id: str, policy: dict[str, Any]) -> None:
    _memory_policy_cache[client_id] = (time.time() + POLICY_CACHE_TTL_SECONDS, copy.deepcopy(policy))


def save_policy(client_id: str, policy: dict[str, Any]) -> None:
    policy["client_id"] = client_id
    save_policy_to_storage(client_id, policy)
    set_policy_cache(client_id, policy)


def new_rule_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def validate_regex(pattern: str, ignore_case: bool) -> None:
    flags = re.IGNORECASE if ignore_case else 0
    try:
        re.compile(pattern, flags)
    except re.error as exc:
        raise HTTPException(status_code=400, detail=f"Regex tidak valid: {exc}") from exc


def normalize_entity_label(label: str, policy: dict[str, Any]) -> str:
    clean_label = label.upper().replace("B-", "").replace("I-", "").replace("_", "-")

    for mapping in policy.get("label_mappings", []):
        if not mapping.get("enabled", True):
            continue

        labels = [str(item).upper().replace("_", "-") for item in mapping.get("labels", [])]
        if any(key in clean_label for key in labels):
            return str(mapping["replacement"])

    return f"[PRIVATE_{clean_label.replace('-', '_')}]"


def extract_span(prediction: dict[str, Any], policy: dict[str, Any]) -> tuple[int, int, str] | None:
    start = prediction.get("start")
    end = prediction.get("end")
    label = prediction.get("entity_group") or prediction.get("entity") or prediction.get("label")

    if start is None or end is None or label is None:
        return None

    return int(start), int(end), normalize_entity_label(str(label), policy)


def merge_spans(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    if not spans:
        return []

    spans = sorted(spans, key=lambda item: (item[0], item[1]))
    merged: list[tuple[int, int, str]] = [spans[0]]

    for start, end, tag in spans[1:]:
        last_start, last_end, last_tag = merged[-1]
        if start <= last_end and tag == last_tag:
            merged[-1] = (last_start, max(last_end, end), last_tag)
        elif start <= last_end:
            merged[-1] = (last_start, max(last_end, end), last_tag)
        else:
            merged.append((start, end, tag))

    return merged


def mask_text(text: str, predictions: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> str:
    active_policy = policy or load_policy()
    spans = [span for item in predictions if (span := extract_span(item, active_policy)) is not None]
    spans.extend(extract_rule_based_spans(text, active_policy))
    merged_spans = merge_spans(spans)

    masked_parts: list[str] = []
    cursor = 0
    last_tag: str | None = None

    for start, end, tag in merged_spans:
        if start < cursor:
            continue

        masked_parts.append(text[cursor:start])
        if tag != last_tag:
            masked_parts.append(tag)
        cursor = end
        last_tag = tag

    masked_parts.append(text[cursor:])
    return "".join(masked_parts)


def extract_rule_based_spans(text: str, policy: dict[str, Any]) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []

    for rule in policy.get("regex_rules", []):
        if not rule.get("enabled", True):
            continue

        flags = re.IGNORECASE if rule.get("ignore_case", False) else 0
        try:
            pattern = re.compile(str(rule["pattern"]), flags)
        except re.error:
            logger.warning("Skipping invalid regex rule %s", rule.get("id"))
            continue

        capture_group = int(rule.get("capture_group", 0))
        tag = str(rule["replacement"])

        for match in pattern.finditer(text):
            if capture_group > 0:
                try:
                    spans.append((match.start(capture_group), match.end(capture_group), tag))
                except IndexError:
                    logger.warning("Skipping regex rule %s with invalid capture group", rule.get("id"))
            else:
                spans.append((match.start(), match.end(), tag))

    return spans


@app.post("/mask-pii", response_model=MaskResponse)
def mask_pii(payload: MaskRequest, request: Request) -> MaskResponse:
    text = payload.text.strip()
    client_id = get_client_id(request)

    if not text:
        raise HTTPException(status_code=400, detail="Field 'text' tidak boleh kosong.")

    try:
        classifier = get_classifier()
    except Exception:
        raise HTTPException(
            status_code=503,
            detail=f"Model belum siap atau gagal dimuat: {_model_load_error}",
        ) from None

    try:
        policy = load_policy(client_id)
        predictions = classifier(text)
        return MaskResponse(masked_text=mask_text(text, predictions, policy))
    except Exception as exc:
        logger.exception("Failed to process text")
        raise HTTPException(
            status_code=500,
            detail=f"Model gagal memproses data: {exc}",
        ) from exc


@app.get("/policy")
def get_policy(request: Request) -> dict[str, Any]:
    return load_policy(get_client_id(request))


@app.post("/policy/regex-rules")
def create_regex_rule(rule: RegexRuleInput, request: Request) -> dict[str, Any]:
    client_id = get_client_id(request)
    validate_regex(rule.pattern, rule.ignore_case)
    policy = load_policy(client_id)
    item = rule.model_dump()
    item["id"] = new_rule_id("regex")
    item["source"] = "user"
    policy.setdefault("regex_rules", []).append(item)
    save_policy(client_id, policy)
    return item


@app.put("/policy/regex-rules/{rule_id}")
def update_regex_rule(rule_id: str, rule: RegexRuleInput, request: Request) -> dict[str, Any]:
    client_id = get_client_id(request)
    validate_regex(rule.pattern, rule.ignore_case)
    policy = load_policy(client_id)

    for index, existing in enumerate(policy.get("regex_rules", [])):
        if existing.get("id") == rule_id:
            item = rule.model_dump()
            item["id"] = rule_id
            item["source"] = existing.get("source", "user")
            policy["regex_rules"][index] = item
            save_policy(client_id, policy)
            return item

    raise HTTPException(status_code=404, detail="Regex rule tidak ditemukan.")


@app.delete("/policy/regex-rules/{rule_id}")
def delete_regex_rule(rule_id: str, request: Request) -> dict[str, str]:
    client_id = get_client_id(request)
    policy = load_policy(client_id)
    rules = policy.get("regex_rules", [])
    filtered = [rule for rule in rules if rule.get("id") != rule_id]

    if len(filtered) == len(rules):
        raise HTTPException(status_code=404, detail="Regex rule tidak ditemukan.")

    policy["regex_rules"] = filtered
    save_policy(client_id, policy)
    return {"status": "deleted"}


@app.post("/policy/label-mappings")
def create_label_mapping(mapping: LabelMappingInput, request: Request) -> dict[str, Any]:
    client_id = get_client_id(request)
    policy = load_policy(client_id)
    item = mapping.model_dump()
    item["id"] = new_rule_id("label")
    item["source"] = "user"
    policy.setdefault("label_mappings", []).append(item)
    save_policy(client_id, policy)
    return item


@app.put("/policy/label-mappings/{mapping_id}")
def update_label_mapping(mapping_id: str, mapping: LabelMappingInput, request: Request) -> dict[str, Any]:
    client_id = get_client_id(request)
    policy = load_policy(client_id)

    for index, existing in enumerate(policy.get("label_mappings", [])):
        if existing.get("id") == mapping_id:
            item = mapping.model_dump()
            item["id"] = mapping_id
            item["source"] = existing.get("source", "user")
            policy["label_mappings"][index] = item
            save_policy(client_id, policy)
            return item

    raise HTTPException(status_code=404, detail="Label mapping tidak ditemukan.")


@app.delete("/policy/label-mappings/{mapping_id}")
def delete_label_mapping(mapping_id: str, request: Request) -> dict[str, str]:
    client_id = get_client_id(request)
    policy = load_policy(client_id)
    mappings = policy.get("label_mappings", [])
    filtered = [mapping for mapping in mappings if mapping.get("id") != mapping_id]

    if len(filtered) == len(mappings):
        raise HTTPException(status_code=404, detail="Label mapping tidak ditemukan.")

    policy["label_mappings"] = filtered
    save_policy(client_id, policy)
    return {"status": "deleted"}


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok" if _classifier is not None else "model_not_ready",
        "model": MODEL_NAME,
        "policy_storage": POLICY_STORAGE,
    }
