# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""LicenseCourt: consensus-bound AI agent license admission for GenLayer."""

from genlayer import *
import hashlib
import json
import typing


class LicenseCourt(gl.Contract):
    license_count: u64
    latest_license_id: str
    licenses: TreeMap[str, str]
    assessments: TreeMap[str, str]
    license_ids: DynArray[str]

    def __init__(self):
        self.license_count = u64(0)
        self.latest_license_id = ""

    @gl.public.view
    def get_license(self, license_id: str) -> str:
        return self.licenses.get(license_id.strip(), "")

    @gl.public.view
    def get_assessment(self, assessment_id: str) -> str:
        return self.assessments.get(assessment_id.strip(), "")

    @gl.public.view
    def get_latest_license_id(self) -> str:
        return self.latest_license_id

    @gl.public.view
    def list_license_ids(self, offset: u64, limit: u64) -> str:
        start, size = int(offset), int(limit)
        if start < 0 or size < 1 or size > 50:
            raise Exception("invalid_page")
        return _canonical_json([self.license_ids[i] for i in range(start, min(start + size, len(self.license_ids)))])

    @gl.public.view
    def preview_license_id(self, owner: str, consumer: str, agent: str, asset_url: str, terms_url: str, scope: str, max_uses: u64, expires_at: u64, nonce: str) -> str:
        canonical = _canonical_license(owner, consumer, agent, asset_url, terms_url, scope, int(max_uses), int(expires_at))
        return "lic_" + _parts(["licensecourt.v1", _canonical_json(canonical), _digest(nonce, "invalid_nonce")])[:24]

    @gl.public.write
    def register_license(self, consumer: str, agent: str, asset_url: str, terms_url: str, source_a: str, source_b: str, scope: str, max_uses: u64, expires_at: u64, nonce: str) -> str:
        now = _now()
        owner = str(gl.message.sender_address).lower()
        canonical = _canonical_license(owner, consumer, agent, asset_url, terms_url, scope, int(max_uses), int(expires_at))
        if now <= 0 or canonical["expires_at"] <= now or canonical["expires_at"] > now + 7_776_000:
            raise Exception("invalid_expiry")
        a, b = _https_url(source_a, "invalid_source_a"), _https_url(source_b, "invalid_source_b")
        if _source_identity(a) == _source_identity(b):
            raise Exception("independent_sources_required")
        nonce_hash = _digest(nonce, "invalid_nonce")
        license_id = "lic_" + _parts(["licensecourt.v1", _canonical_json(canonical), nonce_hash])[:24]
        if self.licenses.get(license_id, ""):
            raise Exception("nonce_already_used")
        self.license_count = u64(int(self.license_count) + 1)
        record = {
            "schema": "licensecourt.v1", "license_id": license_id, "sequence": int(self.license_count),
            "canonical_license": canonical, "license_hash": _sha256(_canonical_json(canonical)),
            "source_urls": [a, b], "source_identities": [_source_identity(a), _source_identity(b)],
            "nonce_hash": nonce_hash, "status": "registered", "uses": 0, "assessment_id": "",
            "challenge": {}, "challenge_history": [], "created_at": now, "updated_at": now,
        }
        self.licenses[license_id] = _canonical_json(record)
        self.license_ids.append(license_id)
        self.latest_license_id = license_id
        return license_id

    @gl.public.write
    def assess_license(self, license_id: str) -> str:
        record = _load(self.licenses, license_id, "unknown_license")
        sender = str(gl.message.sender_address).lower()
        if sender not in (record["canonical_license"]["owner"], record["canonical_license"]["consumer"]):
            raise Exception("only_license_party_can_assess")
        if record["status"] not in ("registered", "challenged"):
            raise Exception("license_not_assessable")
        if _now() <= 0 or _now() >= int(record["canonical_license"]["expires_at"]):
            raise Exception("license_expired")
        context = {"license_id": record["license_id"], "license_hash": record["license_hash"], "canonical_license": record["canonical_license"], "sources": record["source_urls"], "source_identities": record["source_identities"], "challenge": record.get("challenge", {})}

        def leader_fn():
            return _canonical_json(_evaluate(context))

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                proposed = _parse_assessment(leader_result.calldata, context)
                independent = _parse_assessment(_canonical_json(_evaluate(context)), context)
            except Exception:
                return False
            fields = ["decision", "reason_code", "license_hash", "terms_snapshot_hash", "asset_snapshot_hash", "source_bundle_hash", "counterevidence_snapshot_hash", "challenge_commitment", "challenge_bundle_hash", "assessment_hash"]
            return all(proposed[key] == independent[key] for key in fields)

        assessment = _parse_assessment(gl.vm.run_nondet_unsafe(leader_fn, validator_fn), context)
        assessment_id = "asm_" + _parts([record["license_id"], assessment["assessment_hash"], assessment["decision"]])[:24]
        assessment["assessment_id"] = assessment_id
        assessment["license_id"] = record["license_id"]
        assessment["created_at"] = _now()
        self.assessments[assessment_id] = _canonical_json(assessment)
        record["assessment_id"] = assessment_id
        record["status"] = "approved" if assessment["decision"] == "approved" else "denied"
        if context["challenge"]:
            record["challenge_history"].append({"challenge": context["challenge"], "assessment_id": assessment_id, "assessment_hash": assessment["assessment_hash"], "resolved_at": _now()})
        record["challenge"] = {}
        record["updated_at"] = _now()
        self.licenses[record["license_id"]] = _canonical_json(record)
        return assessment_id

    @gl.public.write
    def challenge_license(self, license_id: str, counterevidence_url: str, rationale: str) -> None:
        record = _load(self.licenses, license_id, "unknown_license")
        sender = str(gl.message.sender_address).lower()
        license_data = record["canonical_license"]
        if sender not in (license_data["owner"], license_data["consumer"]):
            raise Exception("only_license_party_can_challenge")
        if record["status"] != "approved" or int(record["uses"]) > 0:
            raise Exception("license_not_challengeable")
        now = _now()
        if now <= 0 or now + 3600 >= int(license_data["expires_at"]):
            raise Exception("challenge_window_closed")
        evidence = _https_url(counterevidence_url, "invalid_counterevidence")
        if _source_identity(evidence) not in record["source_identities"]:
            raise Exception("counterevidence_must_match_registered_source")
        rationale_text = _clean(rationale, 2000, "rationale_required")
        rationale_hash = _sha256(rationale_text)
        record["status"] = "challenged"
        record["challenge"] = {"challenger": sender, "counterevidence_url": evidence, "counterevidence_identity": _source_identity(evidence), "rationale": rationale_text, "rationale_hash": rationale_hash, "challenge_commitment": _sha256(_canonical_json({"license_id": record["license_id"], "challenger": sender, "counterevidence_url": evidence, "rationale_hash": rationale_hash, "opened_at": now})), "opened_at": now, "resolve_after": now + 300, "resolve_before": now + 3600}
        record["updated_at"] = now
        self.licenses[record["license_id"]] = _canonical_json(record)

    @gl.public.write
    def resolve_or_expire(self, license_id: str) -> str:
        record = _load(self.licenses, license_id, "unknown_license")
        now = _now()
        if record["status"] == "challenged":
            challenge = record["challenge"]
            if now < int(challenge["resolve_after"]):
                raise Exception("challenge_cooldown")
            if now > int(challenge["resolve_before"]):
                record["status"], record["challenge"] = "revoked", {"outcome": "challenge_timeout", **challenge}
            else:
                # Re-assessment includes the immutable prior license record and allowed source identity.
                return self.assess_license(license_id)
        elif now >= int(record["canonical_license"]["expires_at"]) and record["status"] in ("registered", "approved", "denied"):
            record["status"] = "expired"
        else:
            raise Exception("nothing_to_resolve")
        record["updated_at"] = now
        self.licenses[record["license_id"]] = _canonical_json(record)
        return record["status"]

    @gl.public.write
    def consume_license(self, license_id: str, usage_payload_hash: str) -> str:
        record = _load(self.licenses, license_id, "unknown_license")
        license_data = record["canonical_license"]
        sender = str(gl.message.sender_address).lower()
        if sender != license_data["agent"]:
            raise Exception("only_named_agent_can_consume")
        if record["status"] != "approved":
            raise Exception("license_not_approved")
        if _now() <= 0 or _now() >= int(license_data["expires_at"]):
            raise Exception("license_expired")
        if int(record["uses"]) >= int(license_data["max_uses"]):
            raise Exception("usage_limit_reached")
        payload = _digest(usage_payload_hash, "invalid_usage_payload_hash")
        next_use = int(record["uses"]) + 1
        receipt_id = "use_" + _parts([record["license_id"], str(next_use), payload])[:24]
        record["uses"] = next_use
        record["last_consumption"] = {"receipt_id": receipt_id, "agent": sender, "usage_payload_hash": payload, "used_at": _now()}
        record["status"] = "consumed" if next_use == int(license_data["max_uses"]) else "approved"
        record["updated_at"] = _now()
        self.licenses[record["license_id"]] = _canonical_json(record)
        return receipt_id

    @gl.public.write
    def revoke_license(self, license_id: str) -> None:
        record = _load(self.licenses, license_id, "unknown_license")
        if str(gl.message.sender_address).lower() != record["canonical_license"]["owner"]:
            raise Exception("only_owner_can_revoke")
        if record["status"] in ("consumed", "expired", "revoked"):
            raise Exception("license_closed")
        record["status"], record["updated_at"] = "revoked", _now()
        self.licenses[record["license_id"]] = _canonical_json(record)


def _evaluate(context: dict) -> dict:
    terms = _render(context["canonical_license"]["terms_url"])
    asset = _render(context["canonical_license"]["asset_url"])
    source_a, source_b = _render(context["sources"][0]), _render(context["sources"][1])
    challenge = context.get("challenge", {})
    counter = _render(challenge["counterevidence_url"]) if challenge else {"readable": True, "content": "", "hash": _sha256("NO_CHALLENGE")}
    challenge_commitment = challenge.get("challenge_commitment", _sha256("NO_CHALLENGE"))
    hashes = {"terms_snapshot_hash": terms["hash"], "asset_snapshot_hash": asset["hash"], "source_bundle_hash": _sha256(_canonical_json([source_a["hash"], source_b["hash"], context["source_identities"]])), "counterevidence_snapshot_hash": counter["hash"], "challenge_commitment": challenge_commitment, "challenge_bundle_hash": _sha256(_canonical_json([challenge_commitment, counter["hash"], challenge.get("rationale_hash", _sha256("NO_CHALLENGE"))]))}
    if not all(item["readable"] for item in (terms, asset, source_a, source_b, counter)):
        return _assessment("inconclusive", "source_unavailable", context, hashes)
    prompt = """You are a strict GenLayer license adjudicator. Review the rendered asset, terms, source pages, and any submitted challenge. For a challenge, treat its counterevidence and rationale as material: deny when they credibly contradict permission, approve only when the challenge is refuted by the committed material, otherwise return inconclusive. Return minified JSON with decision (approved|denied|inconclusive) and reason_code (licensed_scope|terms_conflict|insufficient_evidence|unsafe_source|source_unavailable)."""
    material = {"license": context["canonical_license"], "terms": terms["content"], "asset": asset["content"], "source_a": source_a["content"], "source_b": source_b["content"], "challenge": challenge, "counterevidence": counter["content"]}
    try:
        raw = json.loads(gl.nondet.exec_prompt(prompt + "\n" + _canonical_json(material)))
        decision = str(raw.get("decision", "inconclusive")).lower()
        reason = str(raw.get("reason_code", "insufficient_evidence")).lower()
    except Exception:
        decision, reason = "inconclusive", "unsafe_source"
    if decision not in ("approved", "denied", "inconclusive") or reason not in ("licensed_scope", "terms_conflict", "insufficient_evidence", "unsafe_source", "source_unavailable"):
        decision, reason = "inconclusive", "insufficient_evidence"
    if decision == "approved" and reason != "licensed_scope":
        decision, reason = "inconclusive", "insufficient_evidence"
    return _assessment(decision, reason, context, hashes)


def _assessment(decision: str, reason: str, context: dict, hashes: dict) -> dict:
    out = {"decision": decision, "reason_code": reason, "license_hash": context["license_hash"], **hashes}
    out["assessment_hash"] = _sha256(_canonical_json(out))
    return out


def _parse_assessment(raw: str, context: dict) -> dict:
    value = json.loads(raw)
    if value.get("decision") not in ("approved", "denied", "inconclusive") or value.get("reason_code") not in ("licensed_scope", "terms_conflict", "insufficient_evidence", "unsafe_source", "source_unavailable"):
        raise Exception("invalid_assessment")
    for key in ("license_hash", "terms_snapshot_hash", "asset_snapshot_hash", "source_bundle_hash", "counterevidence_snapshot_hash", "challenge_commitment", "challenge_bundle_hash", "assessment_hash"):
        value[key] = _digest(str(value.get(key, "")), "invalid_assessment_hash")
    if value["license_hash"] != context["license_hash"]:
        raise Exception("license_binding_mismatch")
    rebuilt = dict(value); supplied = rebuilt.pop("assessment_hash")
    if _sha256(_canonical_json(rebuilt)) != supplied:
        raise Exception("assessment_hash_mismatch")
    return value


def _canonical_license(owner, consumer, agent, asset_url, terms_url, scope, max_uses, expires_at):
    if max_uses < 1 or max_uses > 100000:
        raise Exception("invalid_max_uses")
    return {"schema": "licensecourt.license.v1", "owner": str(Address(owner)).lower(), "consumer": str(Address(consumer)).lower(), "agent": str(Address(agent)).lower(), "asset_url": _https_url(asset_url, "invalid_asset_url"), "terms_url": _https_url(terms_url, "invalid_terms_url"), "scope": _clean(scope, 240, "scope_required"), "max_uses": max_uses, "expires_at": expires_at}


def _source_identity(url: str) -> str:
    authority = url[8:].split("/", 1)[0].lower()
    if "@" in authority or ":" in authority or not authority or authority.startswith(".") or authority.endswith("."):
        raise Exception("ambiguous_source_authority")
    host = authority[4:] if authority.startswith("www.") else authority
    labels = host.split(".")
    if len(labels) < 2 or any(not label or not label.replace("-", "").isalnum() for label in labels):
        raise Exception("invalid_source_host")
    return ".".join(labels[-2:])


def _render(url: str) -> dict:
    try:
        content = " ".join(str(gl.nondet.web.render(url, mode="text")).split())
        if len(content) < 80:
            return {"readable": False, "content": "", "hash": _sha256("SOURCE_TOO_SHORT")}
        return {"readable": True, "content": content[:12000], "hash": _sha256(content)}
    except Exception:
        return {"readable": False, "content": "", "hash": _sha256("SOURCE_UNAVAILABLE")}


def _load(records, record_id, error):
    raw = records.get(str(record_id).strip(), "")
    if not raw: raise Exception(error)
    return json.loads(raw)


def _https_url(raw, error):
    value = str(raw).strip()
    if not value.startswith("https://") or len(value) > 500 or any(ch in value for ch in "\n\r\t"):
        raise Exception(error)
    return value


def _clean(raw, limit, error):
    value = " ".join(str(raw).strip().split())
    if not value or len(value) > limit: raise Exception(error)
    return value


def _digest(raw, error):
    value = str(raw).strip().lower()
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value): raise Exception(error)
    return value


def _canonical_json(value): return json.dumps(value, sort_keys=True, separators=(",", ":"))
def _sha256(value): return hashlib.sha256(value.encode("utf-8")).hexdigest()
def _parts(parts: typing.Sequence[str]): return _sha256("".join(str(len(str(x))) + ":" + str(x) for x in parts))
def _now():
    try: return int(gl.block.timestamp)
    except Exception: return 0
