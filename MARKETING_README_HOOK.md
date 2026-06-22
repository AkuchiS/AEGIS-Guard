# AEGIS Guard — README hero hook (v1.1)

_DRAFT — ready for public repo AkuchiS/aegis-guard on Jay's go._

### AEGIS Guard — README hero hook (FREE lead, public repo)

# AEGIS Guard

**Prompt injection lives inside the code your agent reads — Guard finds it before the model does, and fences what it misses.**

When an LLM reviews code, it reasons *through* what it reads — and inside that context window there is no wall between the code and the instructions the model follows. A payload tucked in a clean-looking comment or string stops being data and becomes an instruction the moment the model reasons over it; keyword filters miss it because the string is inert until inference. AEGIS Guard does two things about this: it **detects** the known shapes — AI-addressed directives, simulated-authority escalation, data-as-instruction, agent-tool hijacks (with base64 decode-and-rescan and normalization to defeat payloads split across lines) — and, because detection is never perfect, it **fences** untrusted content so it cannot carry instruction authority even when a novel payload slips past. That structural isolation is the real fix; the detector just raises the attacker's cost. Runs fully offline — nothing leaves your network.

```bash
aegis fence < untrusted.txt      # wrap untrusted content so it can't issue instructions
aegis review path/to/code.py     # scan code for injection before an agent reads it
```

```python
from aegis_guard import scan_text, fence_untrusted, wrap_code_for_review, check_output
```

Validated against a 75-case adversarial red-team corpus. Heuristic and pattern-based: it raises the cost of an attack, not a guarantee against a novel obfuscated payload — use it as one gate in defence-in-depth. Content that legitimately quotes attack strings (security docs, test fixtures) may be flagged by design; a flag means "human, look," not "blocked." MIT licensed.
