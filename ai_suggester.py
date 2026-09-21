"""Local AI Unmapped Line Suggester & Reviewer Approval Workflow (PRD Addendum Section 4 Step 3).
Uses local DistilBERT (66M params, PyTorch CPU) to semantically inspect unmapped lines,
generates structured suggestions, logs to append-only pending_suggestions.json,
and enforces human reviewer approval before writing to trusted_mappings.json.
"""
import datetime
import hashlib
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
import torch
from transformers import AutoModel, AutoTokenizer

BASE = pathlib.Path(__file__).parent.resolve()
RULES_FILE = BASE / "07_Compliance_Scanners" / "Rule_Library" / "extracted" / "Rule_Library" / "vendor_rule_mapping.json"
PENDING_FILE = BASE / "pending_suggestions.json"
TRUSTED_FILE = BASE / "trusted_mappings.json"

MODEL_NAME = "distilbert-base-uncased"
_TOKENIZER = None
_MODEL = None

def get_model():
    global _TOKENIZER, _MODEL
    if _MODEL is None:
        _TOKENIZER = AutoTokenizer.from_pretrained(MODEL_NAME)
        _MODEL = AutoModel.from_pretrained(MODEL_NAME)
        _MODEL.eval()
    return _TOKENIZER, _MODEL

def _get_embedding(text: str) -> torch.Tensor:
    tok, mod = get_model()
    inputs = tok(text, return_tensors="pt", truncation=True, max_length=128)
    with torch.no_grad():
        out = mod(**inputs)
    return out.last_hidden_state.mean(dim=1).squeeze(0)

import ai_model_manager
from ai_model_manager import ModelMode, WorkloadType

_MODEL_MANAGER = ai_model_manager.get_model_manager()

def _generate_rationale_ai(line_clean: str, rule_title: str, csm_field: str, confidence: float, fallback_rationale: str) -> str:
    prompt = (
        "You are a technical writer documenting network device configuration rules.\n"
        "Explain in 1-2 clear, factual sentences why the following CLI configuration line maps to the specified compliance rule and data field.\n\n"
        f"Configuration line: {line_clean}\n"
        f"Target rule: {rule_title}\n"
        f"Target field: {csm_field}\n\n"
        "Rationale:"
    )
    res = _MODEL_MANAGER.generate(
        prompt=prompt,
        workload=WorkloadType.UNMAPPED_LINE_MAPPING,
        fallback_text=fallback_rationale
    )

    if not res.is_fallback and len(res.text) > 20:
        print(f"[suggest_mapping] path=ollama model={res.model_used} mode={res.mode_used.value} chars={len(res.text)} elapsed={res.latency_sec:.1f}s")
        print(f"  AI Rationale: {res.text}")
        return res.text
    else:
        print(f"[suggest_mapping] path=fallback reason={res.fallback_reason} chars={len(fallback_rationale)}")
        return fallback_rationale

def suggest_mapping(unmapped_line: str, rules_context: list = None, vendor: str = "cisco") -> dict:
    vendor_clean = (vendor or "cisco").lower().strip()
    if rules_context is None:
        if RULES_FILE.exists():
            data = json.loads(RULES_FILE.read_text(encoding="utf-8-sig"))
            if vendor_clean == "juniper" and "Juniper Junos" in data.get("vendors", {}):
                rules_context = data["vendors"]["Juniper Junos"]["rules"]
            elif "Cisco IOS-XE" in data.get("vendors", {}):
                rules_context = data["vendors"]["Cisco IOS-XE"]["rules"]
            else:
                rules_context = []
        else:
            rules_context = []

    line_clean = unmapped_line.strip()
    line_emb = _get_embedding(line_clean)

    best_rule_id = None
    best_sim = -1.0
    for r in rules_context:
        title = r.get("check_focus", [""])[0] + " " + " ".join(r.get("configuration_evidence", []))
        rule_emb = _get_embedding(title)
        sim = torch.nn.functional.cosine_similarity(line_emb, rule_emb, dim=0).item()
        if sim > best_sim:
            best_sim = sim
            best_rule_id = r["vendor_rule_id"]

    if best_sim >= 0.82:
        rule_title = best_rule_id
        csm_field = "existing_rule"
        fallback_rat = f"Suggested mapping based on semantic similarity with {best_rule_id}, confidence {int(best_sim * 100)}%."
        rationale = _generate_rationale_ai(line_clean, rule_title, csm_field, best_sim, fallback_rat)
        return {
            "raw_line": line_clean,
            "suggested_rule_id": best_rule_id,
            "suggested_new_rule": None,
            "confidence": round(float(best_sim), 2),
            "rationale": rationale,
            "framework_hints": [{"framework": "CIS", "possible_control_id": "CIS-Existing"}],
            "vendor": vendor_clean
        }

    tokens = line_clean.lower().split()
    if vendor_clean == "juniper":
        if "call-home" in line_clean or "callhome" in line_clean:
            new_rule = {
                "common_rule_id": "COMMON-DIAG-001",
                "vendor_rule_id": "JUNOS-DIAG-001",
                "internalTitle": "Disable unneeded telemetry services (Call Home)",
                "csmFieldChecked": "csm.services.call_home",
                "condition": "equals False",
                "vendor": "juniper"
            }
            confidence = 0.88
            hints = [
                {"framework": "CIS", "possible_control_id": "CIS-1.4.1"}
            ]
        else:
            new_rule = {
                "common_rule_id": "COMMON-SEC-001",
                "vendor_rule_id": f"JUNOS-CUSTOM-{tokens[0].upper() if tokens else 'GEN'}-001",
                "internalTitle": f"Configure security control for {tokens[0] if tokens else 'unrecognized Junos statement'}",
                "csmFieldChecked": f"csm.custom.{tokens[0] if tokens else 'unknown'}",
                "condition": "not_null",
                "vendor": "juniper"
            }
            confidence = max(0.20, round(float(best_sim), 2))
            hints = []
    else:
        if "call-home" in line_clean or "callhome" in line_clean:
            new_rule = {
                "common_rule_id": "COMMON-DIAG-001",
                "vendor_rule_id": "CISCO-DIAG-001",
                "internalTitle": "Disable unneeded diagnostic and telemetry services (Call Home)",
                "csmFieldChecked": "csm.services.call_home",
                "condition": "equals False",
                "vendor": "cisco"
            }
            confidence = 0.88
            hints = [
                {"framework": "CIS", "possible_control_id": "CIS-1.4.1"},
                {"framework": "DISA-STIG", "possible_control_id": "V-215849"}
            ]
        elif "banner" in line_clean:
            new_rule = {
                "common_rule_id": "COMMON-BANNER-001",
                "vendor_rule_id": "CISCO-BANNER-001",
                "internalTitle": "Configure legal warning banner",
                "csmFieldChecked": "csm.management.banner",
                "condition": "not_null",
                "vendor": "cisco"
            }
            confidence = 0.65
            hints = [
                {"framework": "CIS", "possible_control_id": "CIS-1.2.1"},
                {"framework": "DISA-STIG", "possible_control_id": "V-215850"}
            ]
        else:
            new_rule = {
                "common_rule_id": "COMMON-SEC-001",
                "vendor_rule_id": f"CISCO-CUSTOM-{tokens[0].upper() if tokens else 'GEN'}-001",
                "internalTitle": f"Configure security control for {tokens[0] if tokens else 'unrecognized command'}",
                "csmFieldChecked": f"csm.custom.{tokens[0] if tokens else 'unknown'}",
                "condition": "not_null",
                "vendor": "cisco"
            }
            confidence = max(0.20, round(float(best_sim), 2))
            hints = []

    fallback_rat = f"Suggested mapping based on semantic similarity, confidence {int(confidence * 100)}%."
    rationale = _generate_rationale_ai(
        line_clean,
        new_rule["internalTitle"],
        new_rule["csmFieldChecked"],
        confidence,
        fallback_rat
    )

    return {
        "raw_line": line_clean,
        "suggested_rule_id": None,
        "suggested_new_rule": new_rule,
        "confidence": confidence,
        "rationale": rationale,
        "framework_hints": hints,
        "vendor": vendor_clean
    }

import database

def store_suggestion(suggestion: dict, filepath: pathlib.Path = PENDING_FILE, vendor: str = None) -> str:
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    raw_id = f"{suggestion['raw_line']}_{ts}"
    suggestion_id = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]
    sug_vendor = (vendor or suggestion.get("vendor") or "cisco").lower().strip()
    suggestion["vendor"] = sug_vendor

    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(pending_suggestions)")
        cols = [row[1] for row in cur.fetchall()]
        if "vendor" in cols:
            cur.execute('''
                INSERT INTO pending_suggestions (suggestion_id, timestamp, status, suggestion, reviewed_by, reviewed_at, vendor)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (suggestion_id, ts, "pending", json.dumps(suggestion), None, None, sug_vendor))
        else:
            cur.execute('''
                INSERT INTO pending_suggestions (suggestion_id, timestamp, status, suggestion, reviewed_by, reviewed_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (suggestion_id, ts, "pending", json.dumps(suggestion), None, None))
        conn.commit()
    finally:
        conn.close()

    return suggestion_id

def approve_suggestion(suggestion_id: str, reviewer_name: str, decision: str,
                       corrected_mapping: dict = None,
                       pending_file: pathlib.Path = PENDING_FILE,
                       trusted_file: pathlib.Path = TRUSTED_FILE) -> dict:
    if decision not in ("approve", "reject", "approve_with_correction"):
        raise ValueError(f"Invalid decision '{decision}'. Must be approve, reject, or approve_with_correction.")

    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute('SELECT * FROM pending_suggestions WHERE suggestion_id = ?', (suggestion_id,))
        target_entry_row = cur.fetchone()
        
        if target_entry_row is None:
            raise ValueError(f"Suggestion ID '{suggestion_id}' not found.")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if decision == "reject":
            cur.execute('UPDATE pending_suggestions SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE suggestion_id = ?', 
                        ("rejected", reviewer_name, now_iso, suggestion_id))
            conn.commit()
            return {"suggestion_id": suggestion_id, "status": "rejected", "reviewer": reviewer_name}

        sug = json.loads(target_entry_row["suggestion"])
        rule_spec = corrected_mapping if corrected_mapping else sug.get("suggested_new_rule")
        if not rule_spec:
            raise ValueError(f"Suggestion '{suggestion_id}' does not have a new rule to approve.")

        # Determine vendor from rule_spec, suggestion, or table
        target_keys = target_entry_row.keys()
        row_vendor = target_entry_row["vendor"] if "vendor" in target_keys else None
        vrid = rule_spec.get("vendor_rule_id", "")
        inferred = "juniper" if (vrid.startswith("JUNOS-") or vrid.startswith("JUNIPER-")) else "cisco"
        vendor = (rule_spec.get("vendor") or sug.get("vendor") or row_vendor or inferred).lower().strip()

        # Determine rule IDs
        field_checked = rule_spec.get("csmFieldChecked", "")
        if "call_home" in field_checked:
            default_vrid = "JUNOS-DIAG-001" if vendor == "juniper" else "CISCO-DIAG-001"
        else:
            prefix = "JUNOS-CUSTOM" if vendor == "juniper" else "CISCO-CUSTOM"
            slug = hashlib.sha256(rule_spec.get("internalTitle", "RULE").encode()).hexdigest()[:6].upper()
            default_vrid = f"{prefix}-{slug}-001"
        final_vrid = rule_spec.get("vendor_rule_id") or default_vrid
        final_common_id = rule_spec.get("common_rule_id", "COMMON-DIAG-001")

        is_correction = bool(decision == "approve_with_correction" or corrected_mapping)
        source = "ai_suggested"
        status = "corrected" if is_correction else "approved"

        # Conflict check against existing trusted mappings
        cur.execute('SELECT * FROM trusted_mappings WHERE vendor_rule_id = ?', (final_vrid,))
        existing_row = cur.fetchone()
        if existing_row is not None:
            # Deterministic duplicate check
            ex_title = existing_row["internalTitle"]
            ex_field = existing_row["csmFieldChecked"]
            ex_cond = existing_row["condition"]
            
            if (ex_title == rule_spec["internalTitle"] and 
                ex_field == rule_spec["csmFieldChecked"] and 
                ex_cond == rule_spec["condition"]):
                # Identical duplicate -> idempotent success without silent mutation
                cur.execute('UPDATE pending_suggestions SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE suggestion_id = ?', 
                            (decision, reviewer_name, now_iso, suggestion_id))
                conn.commit()
                return database._row_to_trusted_mapping(existing_row)
            else:
                # Conflicting definition -> raise Conflict error to prevent silent overwrite
                raise ValueError(
                    f"Conflict: Trusted mapping for '{final_vrid}' already exists with a conflicting definition. "
                    f"Existing: ({ex_field} {ex_cond}), Proposed: ({rule_spec['csmFieldChecked']} {rule_spec['condition']}). "
                    f"Silent overwrite is prohibited."
                )

        cur.execute('UPDATE pending_suggestions SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE suggestion_id = ?', 
                    (decision, reviewer_name, now_iso, suggestion_id))

        trusted_entry = {
            "common_rule_id": final_common_id,
            "vendor_rule_id": final_vrid,
            "internalTitle": rule_spec["internalTitle"],
            "csmFieldChecked": rule_spec["csmFieldChecked"],
            "condition": rule_spec["condition"],
            "configuration_evidence": [sug["raw_line"]],
            "check_focus": [rule_spec["internalTitle"]],
            "frameworkMappings": sug.get("framework_hints", []),
            "version_info": {
                "version": "1.0",
                "approved_by": reviewer_name,
                "approved_at": now_iso,
                "source": source
            },
            "vendor": vendor,
            "status": status,
            "created_at": now_iso,
            "updated_at": now_iso
        }

        cur.execute("PRAGMA table_info(trusted_mappings)")
        tm_cols = [r[1] for r in cur.fetchall()]
        if "vendor" in tm_cols:
            cur.execute('''
                INSERT INTO trusted_mappings 
                (vendor_rule_id, common_rule_id, internalTitle, csmFieldChecked, condition, configuration_evidence, check_focus, frameworkMappings, version_info, vendor, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                trusted_entry["vendor_rule_id"],
                trusted_entry["common_rule_id"],
                trusted_entry["internalTitle"],
                trusted_entry["csmFieldChecked"],
                trusted_entry["condition"],
                json.dumps(trusted_entry["configuration_evidence"]),
                json.dumps(trusted_entry["check_focus"]),
                json.dumps(trusted_entry["frameworkMappings"]),
                json.dumps(trusted_entry["version_info"]),
                vendor,
                status,
                now_iso,
                now_iso
            ))
        else:
            cur.execute('''
                INSERT INTO trusted_mappings 
                (vendor_rule_id, common_rule_id, internalTitle, csmFieldChecked, condition, configuration_evidence, check_focus, frameworkMappings, version_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                trusted_entry["vendor_rule_id"],
                trusted_entry["common_rule_id"],
                trusted_entry["internalTitle"],
                trusted_entry["csmFieldChecked"],
                trusted_entry["condition"],
                json.dumps(trusted_entry["configuration_evidence"]),
                json.dumps(trusted_entry["check_focus"]),
                json.dumps(trusted_entry["frameworkMappings"]),
                json.dumps(trusted_entry["version_info"])
            ))
        
        conn.commit()
        return trusted_entry
    finally:
        conn.close()

