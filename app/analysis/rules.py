"""MISRA-oriented and secure-coding rule engine for C.

Each rule produces RawFinding objects with evidence (file, function, line) and a rule confidence.
Rule references point to MISRA C:2012 rule numbers / CWE IDs and to internal guideline IDs
(ECU-CS-xx) whose text lives in data/guidelines and is retrieved by the RAG layer.
"""
import re
from dataclasses import dataclass, field

from .c_parser import IDENT, FunctionInfo, ParsedFile, matching_paren, split_args

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

RULES = {
    "SC-NULL-01": dict(title="Allocation result used without NULL check", category="null_pointer", severity="high",
                       misra="Dir 4.1", cwe="CWE-476", guideline="ECU-CS-03",
                       fix="Check the pointer against NULL immediately after allocation and handle the failure path."),
    "SC-NULL-02": dict(title="Pointer parameter dereferenced without validation", category="null_pointer", severity="medium",
                       misra="Dir 4.1", cwe="CWE-476", guideline="ECU-CS-03",
                       fix="Validate pointer parameters at function entry (e.g. `if (p == NULL) { return E_NOT_OK; }`)."),
    "SC-NULL-03": dict(title="Possibly-NULL return value dereferenced", category="null_pointer", severity="high",
                       misra="Dir 4.1", cwe="CWE-690", guideline="ECU-CS-03",
                       fix="The callee can return NULL; check the returned pointer before dereferencing it."),
    "SC-BUF-01": dict(title="Unbounded string/format function", category="buffer_overflow", severity="high",
                      misra="Rule 21.17", cwe="CWE-120", guideline="ECU-CS-04",
                      fix="Use a bounded alternative (snprintf / explicit length check + memcpy) and guarantee NUL termination."),
    "SC-BUF-02": dict(title="Copy length not validated against destination size", category="buffer_overflow", severity="high",
                      misra="Rule 21.18", cwe="CWE-787", guideline="ECU-CS-04",
                      fix="Validate the length against sizeof(destination) before copying and reject oversize input."),
    "SC-BUF-03": dict(title="Array index from parameter without bounds check", category="buffer_overflow", severity="high",
                      misra="Rule 18.1", cwe="CWE-129", guideline="ECU-CS-04",
                      fix="Check the index against the array dimension before use (index < ARRAY_LEN)."),
    "SC-BUF-04": dict(title="Off-by-one loop bound (<=) on array", category="buffer_overflow", severity="high",
                      misra="Rule 18.1", cwe="CWE-193", guideline="ECU-CS-04",
                      fix="Use `<` instead of `<=` when the bound equals the array length."),
    "SC-MEM-01": dict(title="Allocated memory never released", category="resource_leak", severity="medium",
                      misra="Rule 22.1", cwe="CWE-401", guideline="ECU-CS-05",
                      fix="Release the resource on every path or use a statically allocated buffer."),
    "SC-MEM-02": dict(title="Resource leaked on early-return path", category="resource_leak", severity="high",
                      misra="Rule 22.1", cwe="CWE-401", guideline="ECU-CS-05",
                      fix="Free the resource before the early return, or restructure to a single exit with cleanup."),
    "SC-MEM-03": dict(title="Dynamic memory allocation in ECU code", category="api_usage", severity="medium",
                      misra="Rule 21.3", cwe="CWE-770", guideline="ECU-CS-05",
                      fix="Replace heap allocation with statically sized buffers or a qualified memory pool."),
    "SC-UNINIT-01": dict(title="Variable read before initialisation", category="uninitialized", severity="high",
                         misra="Rule 9.1", cwe="CWE-457", guideline="ECU-CS-06",
                         fix="Initialise the variable at declaration (e.g. `= 0`)."),
    "SC-UNINIT-02": dict(title="Variable may be uninitialised on some paths", category="uninitialized", severity="medium",
                         misra="Rule 9.1", cwe="CWE-457", guideline="ECU-CS-06",
                         fix="Initialise the variable at declaration so every path has a defined value."),
    "SC-DIV-01": dict(title="Division by unchecked divisor", category="div_by_zero", severity="high",
                      misra="Dir 4.1", cwe="CWE-369", guideline="ECU-CS-08",
                      fix="Guard the division with an explicit non-zero check and define the fallback value."),
    "SC-INT-01": dict(title="Arithmetic result narrowed to small integer type", category="integer_overflow", severity="medium",
                      misra="Rule 10.3", cwe="CWE-197", guideline="ECU-CS-08",
                      fix="Compute in a wider type, range-check (saturate) and cast explicitly."),
    "SC-INT-02": dict(title="Unchecked multiplication in allocation size", category="integer_overflow", severity="high",
                      misra="Rule 12.4", cwe="CWE-190", guideline="ECU-CS-08",
                      fix="Check `count <= MAX / size` before multiplying for an allocation size."),
    "SC-ISR-01": dict(title="Shared variable written in ISR is not volatile", category="concurrency", severity="high",
                      misra="Dir 5.1", cwe="CWE-662", guideline="ECU-CS-07",
                      fix="Declare the shared variable `volatile` and protect multi-byte accesses."),
    "SC-ISR-02": dict(title="ISR-shared data modified outside critical section", category="concurrency", severity="medium",
                      misra="Dir 5.1", cwe="CWE-362", guideline="ECU-CS-07",
                      fix="Wrap the read-modify-write in a critical section (disable/enable interrupts)."),
    "SC-CF-01": dict(title="switch without default clause", category="control_flow", severity="medium",
                     misra="Rule 16.4", cwe="CWE-478", guideline="ECU-CS-02",
                     fix="Add a `default:` clause that handles unexpected values (e.g. enter safe state)."),
    "SC-CF-02": dict(title="goto statement used", category="control_flow", severity="low",
                     misra="Rule 15.1", cwe="", guideline="ECU-CS-02",
                     fix="Restructure using structured control flow."),
    "SC-CF-03": dict(title="Recursive function call", category="control_flow", severity="medium",
                     misra="Rule 17.2", cwe="CWE-674", guideline="ECU-CS-02",
                     fix="Replace recursion with an iterative loop with a fixed upper bound."),
    "SC-CF-04": dict(title="Control statement body without braces", category="control_flow", severity="low",
                     misra="Rule 15.6", cwe="CWE-483", guideline="ECU-CS-02",
                     fix="Always enclose if/else/loop bodies in braces."),
    "SC-CF-05": dict(title="Assignment used inside a condition", category="control_flow", severity="high",
                     misra="Rule 13.4", cwe="CWE-481", guideline="ECU-CS-02",
                     fix="Move the assignment out of the condition, or use `==` if a comparison was intended."),
    "SC-CF-06": dict(title="Multiple exit points in function", category="control_flow", severity="low",
                     misra="Rule 15.5", cwe="", guideline="ECU-CS-02",
                     fix="Prefer a single return at the end of the function (advisory)."),
    "SC-API-01": dict(title="Return value of function ignored", category="api_usage", severity="medium",
                      misra="Rule 17.7", cwe="CWE-252", guideline="ECU-CS-09",
                      fix="Check the returned status or explicitly cast to (void) with a justification."),
    "SC-API-02": dict(title="Standard I/O used in ECU code", category="api_usage", severity="low",
                      misra="Rule 21.6", cwe="", guideline="ECU-CS-09",
                      fix="Use the platform diagnostic/logging service instead of stdio."),
    "SC-API-03": dict(title="atoi/atof family used", category="api_usage", severity="medium",
                      misra="Rule 21.7", cwe="CWE-190", guideline="ECU-CS-09",
                      fix="Use strtol/strtoul with end-pointer and range checks."),
    "SC-SEC-01": dict(title="Hard-coded credential or key", category="security", severity="critical",
                      misra="", cwe="CWE-798", guideline="ECU-SEC-01",
                      fix="Load keys from the HSM / secure storage; never embed secrets in source."),
    "SC-SEC-02": dict(title="Non-literal format string", category="security", severity="high",
                      misra="", cwe="CWE-134", guideline="ECU-SEC-02",
                      fix="Use a literal format string, e.g. printf(\"%s\", msg)."),
    "SC-SEC-03": dict(title="Prompt-injection-like text in repository content", category="security", severity="medium",
                      misra="", cwe="CWE-1427", guideline="ECU-SEC-04",
                      fix="Remove the instruction-like comment; it was quarantined and excluded from AI context."),
    "SC-ML-DEF": dict(title="ML-suspected defect pattern", category="ml_signal", severity="medium",
                      misra="", cwe="", guideline="ECU-CS-10",
                      fix="Review the function for the predicted defect class; confirm or reject to improve the model."),
    "SC-ML-CPLX": dict(title="Complexity hotspot (anomalous function)", category="maintainability", severity="low",
                       misra="Dir 4.1", cwe="CWE-1121", guideline="ECU-CS-10",
                       fix="Split the function into smaller units and add targeted unit tests."),
}

INT_TYPES = r"(?:unsigned\s+|signed\s+)?(?:int|char|short|long|float|double|bool|_Bool|u?int(?:8|16|32|64)_t|uint8|uint16|uint32|sint8|sint16|sint32|boolean|float32|float64|[A-Za-z_]\w*_t)"
CRITICAL_SECTION = r"\b(DisableInterrupts|EnableInterrupts|__disable_irq|__enable_irq|SuspendAllInterrupts|ResumeAllInterrupts|SchM_Enter\w*|Enter_Critical\w*|ENTER_CRITICAL\w*|osal_lock\w*)\s*\("
ISR_NAME = re.compile(r"(ISR|Isr|_isr|IRQHandler|_Handler|Interrupt)")


@dataclass
class RawFinding:
    rule_id: str
    file_path: str
    line: int
    function: str | None
    message: str
    evidence: str
    rule_conf: float
    category: str = ""
    severity: str = ""
    title: str = ""
    misra_ref: str = ""
    cwe: str = ""
    guideline: str = ""
    suggested_fix: str = ""
    sources: list = field(default_factory=lambda: ["rules"])

    def __post_init__(self):
        meta = RULES[self.rule_id]
        self.category = self.category or meta["category"]
        self.severity = self.severity or meta["severity"]
        self.title = self.title or meta["title"]
        self.misra_ref = self.misra_ref or meta["misra"]
        self.cwe = self.cwe or meta["cwe"]
        self.guideline = self.guideline or meta["guideline"]
        self.suggested_fix = self.suggested_fix or meta["fix"]


# ------------------------------------------------------------------ helpers
def _line(pf: ParsedFile, fn: FunctionInfo, rel: int) -> int:
    return pf.line_of(fn.body_start + rel)


def _make(pf, fn, rel, rule_id, message, conf, **kw) -> RawFinding:
    ln = _line(pf, fn, rel) if fn is not None else rel
    return RawFinding(rule_id=rule_id, file_path=pf.path, line=ln, function=fn.name if fn else None,
                      message=message, evidence=pf.line_text(ln).strip(), rule_conf=conf, **kw)


def _null_checked(text: str, v: str) -> re.Match | None:
    v = re.escape(v)
    pat = (rf"\b{v}\s*[!=]=\s*(NULL|0|NULL_PTR|nullptr)\b|\b(NULL|NULL_PTR)\s*[!=]=\s*{v}\b|!\s*{v}\b"
           rf"|\(\s*{v}\s*(\)|&&|\|\|)")
    return re.search(pat, text)


def _first_deref(text: str, v: str) -> re.Match | None:
    v = re.escape(v)
    return re.search(rf"\b{v}\s*->|\b{v}\s*\[|\*\s*{v}\b(?!\s*=\s*\w*alloc)|\b(?:mem\w+|str\w+)\s*\(\s*{v}\b", text)


def _range_checked(text: str, v: str) -> bool:
    v = re.escape(v)
    return bool(re.search(rf"\b{v}\s*(<|<=|>|>=)|(<|<=|>|>=)\s*\b{v}\b", text))


def _depth_at(text: str, pos: int) -> int:
    return text[:pos].count("{") - text[:pos].count("}")


# ------------------------------------------------------------------ rules
def rule_unsafe_string(pf, fn, ctx):
    out = []
    for m in re.finditer(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(", fn.masked_body):
        name = m.group(1)
        sev = "critical" if name == "gets" else None
        out.append(_make(pf, fn, m.start(), "SC-BUF-01",
                         f"`{name}` performs no bounds checking on the destination buffer.", 0.9,
                         **({"severity": sev} if sev else {})))
    return out


def rule_copy_length(pf, fn, ctx):
    out = []
    pnames = {p["name"] for p in fn.params if not p["pointer"]}
    for m in re.finditer(r"\bmem(cpy|move)\s*\(", fn.masked_body):
        close = matching_paren(fn.masked_body, m.end() - 1)
        args = split_args(fn.masked_body[m.end():close])
        if len(args) != 3:
            continue
        length = args[2]
        ids = set(re.findall(IDENT, length)) - {"sizeof"}
        tainted = ids & pnames
        if "sizeof" in length or not tainted:
            continue
        before = fn.masked_body[:m.start()]
        if not any(_range_checked(before, t) for t in tainted):
            out.append(_make(pf, fn, m.start(), "SC-BUF-02",
                             f"Length `{length}` comes from a parameter and is not checked before `mem{m.group(1)}`.", 0.82))
    return out


def rule_index_param(pf, fn, ctx):
    out = []
    for p in fn.params:
        if p["pointer"]:
            continue
        v = re.escape(p["name"])
        m = re.search(rf"\b{IDENT}\s*\[\s*{v}\s*\]", fn.masked_body)
        if m and not _range_checked(fn.masked_body[:m.start()], p["name"]):
            out.append(_make(pf, fn, m.start(), "SC-BUF-03",
                             f"Parameter `{p['name']}` is used as an array index without a bounds check.", 0.7))
    return out


def rule_off_by_one(pf, fn, ctx):
    out = []
    arrays = dict(ctx["arrays"])
    for m in re.finditer(rf"\b{INT_TYPES}\s+({IDENT})\s*\[\s*([^\]]+?)\s*\]\s*[;=]", fn.masked_body):
        arrays[m.group(1)] = m.group(2)
    for m in re.finditer(rf"\bfor\s*\(\s*(?:{INT_TYPES}\s+)?({IDENT})\s*=\s*0[uU]?\s*;\s*\1\s*<=\s*([^;]+?)\s*;", fn.masked_body):
        var, bound = m.group(1), m.group(2).strip()
        idx = list(re.finditer(rf"\b({IDENT})\s*\[\s*{re.escape(var)}\s*\]", fn.masked_body[m.end():]))
        if not idx:
            continue
        exact = any(arrays.get(i.group(1)) == bound or f"sizeof({i.group(1)})" in bound.replace(" ", "") for i in idx)
        out.append(_make(pf, fn, m.start(), "SC-BUF-04",
                         f"Loop runs while `{var} <= {bound}` and indexes an array with `{var}`; the last iteration is out of bounds.",
                         0.92 if exact else 0.6))
    return out


ALLOC_RE = re.compile(rf"\b({IDENT})\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(")


def rule_alloc(pf, fn, ctx):
    out = []
    body = fn.masked_body
    for m in ALLOC_RE.finditer(body):
        v = m.group(1)
        out.append(_make(pf, fn, m.start(2), "SC-MEM-03", f"`{m.group(2)}` is used; heap allocation is restricted in ECU software.", 0.95))
        after = body[m.end():]
        use, chk = _first_deref(after, v), _null_checked(after, v)
        if use and (not chk or chk.start() > use.start()):
            out.append(_make(pf, fn, m.end() + use.start(), "SC-NULL-01",
                             f"`{v}` from `{m.group(2)}` is dereferenced before any NULL check.", 0.88))
        close = matching_paren(body, m.end() - 1)
        size_expr = body[m.end():close]
        if re.search(rf"{IDENT}\s*\*\s*{IDENT}", size_expr) and not re.search(r"SIZE_MAX|UINT\w*_MAX|/\s*sizeof", body[:m.start()]):
            out.append(_make(pf, fn, m.start(2), "SC-INT-02", f"Allocation size `{size_expr.strip()}` can overflow.", 0.72))
        free_m = re.search(rf"\bfree\s*\(\s*{re.escape(v)}\s*\)", after)
        escapes = re.search(rf"return\s+{re.escape(v)}\b|=\s*{re.escape(v)}\s*;|->\s*\w+\s*=\s*{re.escape(v)}", after)
        if not free_m and not escapes:
            out.append(_make(pf, fn, m.start(), "SC-MEM-01", f"`{v}` is allocated but never freed in `{fn.name}`.", 0.78))
        elif free_m:
            for r in re.finditer(r"\breturn\b[^;]*;", after[:free_m.start()]):
                if not re.search(rf"\breturn\s+{re.escape(v)}\b", r.group(0)):
                    out.append(_make(pf, fn, m.end() + r.start(), "SC-MEM-02",
                                     f"Early return leaks `{v}` (freed only later in the function).", 0.84))
                    break
    for m in re.finditer(rf"\b({IDENT})\s*=\s*fopen\s*\(", body):
        v = m.group(1)
        if not re.search(rf"\bfclose\s*\(\s*{re.escape(v)}\s*\)", body):
            out.append(_make(pf, fn, m.start(), "SC-MEM-01", f"File handle `{v}` is never closed.", 0.8,
                             title="Resource handle never released", cwe="CWE-775"))
    return out


def rule_param_null(pf, fn, ctx):
    out = []
    body = fn.masked_body
    for p in fn.params:
        if not p["pointer"] or "[" in p["type"]:
            continue
        use = _first_deref(body, p["name"])
        if not use:
            continue
        chk = _null_checked(body, p["name"])
        if not chk or chk.start() > use.start():
            out.append(_make(pf, fn, use.start(), "SC-NULL-02",
                             f"Pointer parameter `{p['name']}` is dereferenced without a NULL check.", 0.55))
    return out


def rule_nullable_return(pf, fn, ctx):
    out = []
    for name in ctx["nullable_funcs"]:
        for m in re.finditer(rf"\b({IDENT})\s*=\s*{re.escape(name)}\s*\(", fn.masked_body):
            v = m.group(1)
            after = fn.masked_body[m.end():]
            use, chk = _first_deref(after, v), _null_checked(after, v)
            if use and (not chk or chk.start() > use.start()):
                out.append(_make(pf, fn, m.end() + use.start(), "SC-NULL-03",
                                 f"`{name}()` can return NULL (repository-aware), but `{v}` is dereferenced unchecked.", 0.85))
    return out


DECL_RE = re.compile(rf"(?:^|[;{{}}])\s*(?:const\s+)?(?P<type>{INT_TYPES})\s+(?P<names>{IDENT}(?:\s*,\s*{IDENT})*)\s*;")


def rule_uninit(pf, fn, ctx):
    out = []
    body = fn.masked_body
    for d in DECL_RE.finditer(body):
        decl_depth = _depth_at(body, d.start("names"))
        for v in [n.strip() for n in d.group("names").split(",")]:
            if v in ("return", "else"):
                continue
            rest_off = d.end()
            occ = list(re.finditer(rf"(?<![\w.>])\b{re.escape(v)}\b", body[rest_off:]))
            if not occ:
                continue
            if any(body[rest_off + o.start() - 1] == "&" for o in occ if rest_off + o.start() > 0):
                continue  # address taken: initialised via out-parameter
            wrote_conditionally = False
            for o in occ:
                pos = rest_off + o.start()
                tail = body[pos + len(v):pos + len(v) + 3]
                is_write = bool(re.match(r"\s*=(?!=)", tail))
                stmt_start = max(body.rfind(";", 0, pos), body.rfind("{", 0, pos), body.rfind("}", 0, pos))
                prefix = body[stmt_start + 1:pos]
                if is_write and re.search(r"\bfor\s*\(\s*$", prefix) and _depth_at(body, pos) == decl_depth:
                    break  # for-loop initialiser always executes
                cond_stmt = bool(re.search(r"\b(if|else|for|while|case)\b", prefix))
                deeper = _depth_at(body, pos) > decl_depth
                if is_write:
                    if deeper or cond_stmt:
                        wrote_conditionally = True
                        continue
                    break  # unconditional write before any read
                if not wrote_conditionally:
                    out.append(_make(pf, fn, pos, "SC-UNINIT-01", f"`{v}` is read before it is assigned a value.", 0.85))
                elif not deeper:
                    out.append(_make(pf, fn, pos, "SC-UNINIT-02",
                                     f"`{v}` is only assigned on some paths before this read.", 0.68))
                break
    return out


def rule_div(pf, fn, ctx):
    out = []
    body = fn.masked_body
    local_names = {p["name"] for p in fn.params} | set(re.findall(rf"\b{INT_TYPES}\s+({IDENT})\s*[=;]", body))
    reported = set()
    for m in re.finditer(rf"(?<![/*])\s[/%]\s*\(?\s*({IDENT})\b(?!\s*\()", body):
        v = m.group(1)
        if v in reported or v.isupper() or v not in local_names:
            continue
        before = body[:m.start()]
        guard = re.search(rf"\b{re.escape(v)}\s*(!=|==|>|<=|>=|<)\s*0|\b0[uU]?\s*(!=|==|<|>)\s*{re.escape(v)}\b|if\s*\(\s*!?\s*{re.escape(v)}\s*\)|\b{re.escape(v)}\s*>\s*\w", before)
        if not guard:
            reported.add(v)
            out.append(_make(pf, fn, m.start() + 1, "SC-DIV-01", f"Divisor `{v}` may be zero; no guard precedes the division.", 0.78))
    return out


def rule_narrowing(pf, fn, ctx):
    out = []
    for m in re.finditer(rf"\b(u?int(?:8|16)_t|uint8|uint16|sint8|sint16)\s+({IDENT})\s*=\s*([^;]+);", fn.masked_body):
        expr = m.group(3)
        if re.search(r"[A-Za-z_]\w*\s*[\+\*]\s*[A-Za-z_0-9]", expr) and not re.match(rf"\s*\(\s*{m.group(1)}\s*\)", expr):
            out.append(_make(pf, fn, m.start(), "SC-INT-01",
                             f"`{expr.strip()}` is computed in a wider type and silently truncated to `{m.group(1)}`.", 0.6))
    return out


def rule_isr(pf, fn, ctx):
    out = []
    if not ISR_NAME.search(fn.name):
        return out
    for g, info in ctx["globals"].items():
        if info["const"]:
            continue
        m = re.search(rf"\b{re.escape(g)}\s*(\[[^\]]*\])?\s*(=(?!=)|\+=|-=|\|=|&=|\+\+|--)|(\+\+|--)\s*{re.escape(g)}\b", fn.masked_body)
        if m:
            ctx["isr_shared"].add(g)
            if not info["volatile"]:
                out.append(_make(pf, fn, m.start(), "SC-ISR-01",
                                 f"`{g}` is written in interrupt handler `{fn.name}` but is not declared volatile.", 0.86))
    return out


def rule_isr_shared_rmw(pf, fn, ctx):
    out = []
    if ISR_NAME.search(fn.name) or re.search(CRITICAL_SECTION, fn.masked_body):
        return out
    for g in ctx["isr_shared"]:
        m = re.search(rf"\b{re.escape(g)}\s*(=(?!=)|\+=|-=|\+\+|--)|(\+\+|--)\s*{re.escape(g)}\b", fn.masked_body)
        if m:
            out.append(_make(pf, fn, m.start(), "SC-ISR-02",
                             f"`{g}` is shared with an ISR and modified here without a critical section.", 0.64))
    return out


def rule_control_flow(pf, fn, ctx):
    out = []
    body = fn.masked_body
    for m in re.finditer(r"\bswitch\s*\(", body):
        close = matching_paren(body, m.end() - 1)
        brace = body.find("{", close)
        end = matching_paren(body, brace, "{", "}") if brace != -1 else -1
        if brace != -1 and end != -1 and not re.search(r"\bdefault\s*:", body[brace:end]):
            out.append(_make(pf, fn, m.start(), "SC-CF-01", "switch statement has no `default` clause.", 0.95))
    for m in re.finditer(r"\bgoto\s+\w+", body):
        out.append(_make(pf, fn, m.start(), "SC-CF-02", "`goto` makes control flow harder to verify.", 0.95))
    rec = re.search(rf"\b{re.escape(fn.name)}\s*\(", body)
    if rec:
        out.append(_make(pf, fn, rec.start(), "SC-CF-03", f"`{fn.name}` calls itself; stack usage is unbounded.", 0.92))
    for m in re.finditer(r"\b(if|while|for)\s*\(", body):
        close = matching_paren(body, m.end() - 1)
        if close == -1:
            continue
        nxt = body[close + 1:].lstrip()
        if nxt and nxt[0] not in "{;":
            out.append(_make(pf, fn, m.start(), "SC-CF-04", f"`{m.group(1)}` body is not enclosed in braces.", 0.9))
        if m.group(1) in ("if", "while"):
            cond = body[m.end():close]
            if re.search(r"(?<![=!<>+\-*/%&|^])=(?!=)", cond):
                out.append(_make(pf, fn, m.start(), "SC-CF-05", "Condition contains an assignment (`=`); was `==` intended?", 0.75))
    for m in re.finditer(r"\belse\b", body):
        nxt = body[m.end():].lstrip()
        if nxt and nxt[0] != "{" and not nxt.startswith("if"):
            out.append(_make(pf, fn, m.start(), "SC-CF-04", "`else` body is not enclosed in braces.", 0.9))
    if fn.metrics["returns"] > 1:
        first = next(re.finditer(r"\breturn\b", body))
        out.append(_make(pf, fn, first.start(), "SC-CF-06",
                         f"`{fn.name}` has {fn.metrics['returns']} return statements.", 0.9))
    return out


def rule_api(pf, fn, ctx):
    out = []
    body = fn.masked_body
    for m in re.finditer(rf"(?:^|[;{{}}])\s*({IDENT})\s*\(", body):
        name = m.group(1)
        if name in ctx["nonvoid_funcs"] or name in ("fwrite", "fread", "fclose", "remove", "rename"):
            close = matching_paren(body, m.end() - 1)
            if close != -1 and body[close + 1:].lstrip().startswith(";"):
                out.append(_make(pf, fn, m.start(1), "SC-API-01",
                                 f"Return value of `{name}()` is discarded.", 0.74 if name in ctx["nonvoid_funcs"] else 0.6))
    stdio = re.search(r"\b(printf|fprintf|puts|scanf|fopen|getchar)\s*\(", body)
    if stdio:
        out.append(_make(pf, fn, stdio.start(), "SC-API-02", f"`{stdio.group(1)}` from <stdio.h> used.", 0.95))
    for m in re.finditer(r"\b(atoi|atol|atoll|atof)\s*\(", body):
        out.append(_make(pf, fn, m.start(), "SC-API-03", f"`{m.group(1)}` has undefined behaviour on overflow and no error reporting.", 0.95))
    for m in re.finditer(rf"\b(printf|syslog)\s*\(\s*({IDENT})\s*\)|\b(fprintf|sprintf)\s*\(\s*{IDENT}\s*,\s*({IDENT})\s*\)", body):
        out.append(_make(pf, fn, m.start(), "SC-SEC-02", "Format string is a variable and may be attacker-controlled.", 0.85))
    return out


SECRET_RE = re.compile(r"\b(\w*(?:key|password|passwd|secret|token|seed|pin)\w*)\s*(\[[^\]]*\])?\s*=\s*(\"[^\"]{4,}\"|\{\s*0x[0-9A-Fa-f]{2})", re.I)


def rule_secrets(pf, ctx):
    out = []
    for m in SECRET_RE.finditer(pf.source):
        masked_slice = pf.masked[m.start():m.start(1) + len(m.group(1))]
        if not masked_slice.strip():  # inside a comment
            continue
        ln = pf.line_of(m.start())
        out.append(RawFinding(rule_id="SC-SEC-01", file_path=pf.path, line=ln,
                              function=(pf.function_at(ln).name if pf.function_at(ln) else None),
                              message=f"`{m.group(1)}` is initialised with an embedded secret value.",
                              evidence=pf.line_text(ln).strip(), rule_conf=0.82))
    return out


FUNCTION_RULES = [rule_unsafe_string, rule_copy_length, rule_index_param, rule_off_by_one, rule_alloc, rule_param_null,
                  rule_nullable_return, rule_uninit, rule_div, rule_narrowing, rule_control_flow, rule_api]


def build_repo_context(parsed_files: list[ParsedFile]) -> dict:
    nonvoid, nullable, arrays, globals_ = set(), set(), {}, {}
    for pf in parsed_files:
        for fn in pf.functions:
            if not fn.returns_void and not fn.name.startswith("main"):
                nonvoid.add(fn.name)
            if "*" in fn.return_type:
                if re.search(r"\breturn\s+(NULL|NULL_PTR|0)\s*;", fn.masked_body):
                    nullable.add(fn.name)
                for rv in re.findall(rf"\breturn\s+({IDENT})\s*;", fn.masked_body):
                    if re.search(rf"\b{rv}\s*=\s*(NULL|NULL_PTR)\b", fn.masked_body):
                        nullable.add(fn.name)
        for name, g in pf.globals.items():
            globals_[name] = g
            if g["array"]:
                arrays[name] = g["array"]
    return {"nonvoid_funcs": nonvoid, "nullable_funcs": nullable, "arrays": arrays, "globals": globals_, "isr_shared": set()}


def run_rules(parsed_files: list[ParsedFile]) -> list[RawFinding]:
    ctx = build_repo_context(parsed_files)
    findings: list[RawFinding] = []
    # ISR pass first so shared-variable knowledge is repository-wide
    for pf in parsed_files:
        file_ctx = dict(ctx, globals={**ctx["globals"], **pf.globals})
        for fn in pf.functions:
            findings += rule_isr(pf, fn, file_ctx)
    for pf in parsed_files:
        file_ctx = dict(ctx, globals={**ctx["globals"], **pf.globals})
        for fn in pf.functions:
            for rule in FUNCTION_RULES:
                findings += rule(pf, fn, file_ctx)
            findings += rule_isr_shared_rmw(pf, fn, ctx)
        findings += rule_secrets(pf, ctx)
    seen, unique = set(), []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
