"""
AEGIS Guard — Output QC
=======================
Quality-control the *output* of your LLM/agent before it reaches a user or another
tool. Catches the failure modes that erode trust: empty/truncated replies, accidental
refusals, leaked secrets or system prompt, invalid JSON when JSON was required, and
low-effort "slop" phrasing. Heuristic and offline by default; pass an llm_judge
callable for an optional second opinion.

    from aegis.output_qc import check_output
    r = check_output(model_reply, require_json=True)
    if not r["pass"]:
        ...   # regenerate / flag

Returns: {"pass": bool, "score": 0-100, "issues": [...], "action": "pass|flag|reject"}
"""
from __future__ import annotations
import json
import re
import sys
from typing import Callable, Dict, List, Optional

_REFUSAL = re.compile(r"\b(i\s+can'?t|i\s+cannot|i'?m\s+unable|i\s+am\s+not\s+able|as\s+an\s+ai\s+language\s+model)\b", re.I)
_SECRET_LEAK = re.compile(r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{10,})", re.I)
_SYSPROMPT_LEAK = re.compile(r"\b(my\s+system\s+prompt|my\s+instructions\s+are|i\s+was\s+instructed\s+to|the\s+developer\s+(?:message|told))\b", re.I)
_SLOP = re.compile(r"\b(as an ai|i hope this helps|in today'?s fast-paced|leverage|synergy|game-?changer|unlock the power|dive into|it'?s important to note that|certainly!|great question)\b", re.I)
_TRUNCATED = re.compile(r"[A-Za-z0-9,]\s*$")  # ends mid-word/clause, no terminal punctuation


def _valid_json(text: str) -> bool:
    t = text.strip()
    # tolerate ```json fences
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t).strip()
    try:
        json.loads(t)
        return True
    except Exception:
        return False


def check_output(text: str, *, require_json: bool = False, min_chars: int = 1,
                 allow_refusal: bool = False, llm_judge: Optional[Callable[[str], Dict]] = None) -> Dict:
    text = text or ""
    issues: List[Dict] = []
    score = 100

    if len(text.strip()) < max(1, min_chars):
        issues.append({"id": "empty", "sev": "high", "msg": f"output shorter than {min_chars} chars"}); score -= 60
    if _SECRET_LEAK.search(text):
        issues.append({"id": "secret_leak", "sev": "critical", "msg": "output appears to contain a live secret/key"}); score -= 80
    if _SYSPROMPT_LEAK.search(text):
        issues.append({"id": "sysprompt_leak", "sev": "high", "msg": "output may be leaking system-prompt/instructions"}); score -= 40
    if not allow_refusal and _REFUSAL.search(text):
        issues.append({"id": "refusal", "sev": "med", "msg": "unexpected refusal / 'as an AI' boilerplate"}); score -= 25
    if require_json and not _valid_json(text):
        issues.append({"id": "bad_json", "sev": "high", "msg": "JSON required but output is not valid JSON"}); score -= 50
    if len(text) > 40 and _TRUNCATED.search(text) and not text.strip().endswith(("}", "]", ")", "`")):
        issues.append({"id": "truncated", "sev": "med", "msg": "output looks truncated (no terminal punctuation)"}); score -= 20
    slop = _SLOP.findall(text)
    if slop:
        issues.append({"id": "slop", "sev": "low", "msg": f"low-effort 'slop' phrasing: {sorted(set(s.lower() for s in slop))[:5]}"}); score -= 8 * min(3, len(set(slop)))

    if llm_judge:
        try:
            j = llm_judge(text) or {}
            if isinstance(j, dict) and j.get("score") is not None:
                score = int(round((score + int(j["score"])) / 2))
                if j.get("issue"):
                    issues.append({"id": "llm_judge", "sev": "med", "msg": str(j["issue"])})
        except Exception as e:
            issues.append({"id": "llm_judge_error", "sev": "low", "msg": f"judge unavailable: {e}"})

    score = max(0, min(100, score))
    crit = any(i["sev"] in ("critical", "high") for i in issues)
    action = "reject" if (crit or score < 50) else ("flag" if score < 80 else "pass")
    return {"pass": action == "pass", "score": score, "action": action, "issues": issues}


def selftest() -> int:
    print("=== AEGIS output-qc self-test ===")
    cases = [
        ("Here are the top 3 product lines: A, B, and C. Let me know if you need a breakdown.", {}, True),
        ("As an AI language model, I can't help with that.", {}, False),
        ('{"verdict": "advance", "score": 7}', {"require_json": True}, True),
        ("advance, score 7", {"require_json": True}, False),
        ("Sure! Here is the api key: sk-abc123abc123abc123abc123 you can use it", {}, False),
    ]
    fails = 0
    for i, (t, kw, want_pass) in enumerate(cases, 1):
        r = check_output(t, **kw); ok = r["pass"] == want_pass; fails += 0 if ok else 1
        print(f"[{i}] {'PASS' if ok else 'FAIL'} expect_pass={want_pass} got pass={r['pass']} action={r['action']} score={r['score']} issues={[x['id'] for x in r['issues']]}")
    print(f"--- {len(cases) - fails}/{len(cases)} passed ---")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(selftest())
