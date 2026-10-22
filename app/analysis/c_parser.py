"""Lightweight C source parser: comment/string masking, function extraction, metrics and globals.

It is intentionally dependency-free (no libclang) so it runs anywhere, and robust enough for
typical embedded C (ECU style) code.
"""
import bisect
import re
from dataclasses import dataclass, field

CONTROL_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else", "case", "goto",
    "defined", "_Alignof", "__attribute__", "typeof",
}
NON_CALLS = CONTROL_KEYWORDS | {"int", "char", "void", "float", "double", "long", "short", "unsigned", "signed"}
IDENT = r"[A-Za-z_]\w*"


@dataclass
class FunctionInfo:
    name: str
    return_type: str
    params: list  # list of dicts: {type, name, pointer}
    signature: str
    start_line: int
    end_line: int
    body_start: int  # file offset of the opening brace
    body_end: int  # file offset of the closing brace
    body: str  # raw body text (between braces, inclusive)
    masked_body: str  # comment/string masked body
    metrics: dict = field(default_factory=dict)
    calls: list = field(default_factory=list)

    @property
    def returns_void(self) -> bool:
        rt = self.return_type.replace("static", "").replace("inline", "").strip()
        return rt == "void"


@dataclass
class ParsedFile:
    path: str
    source: str
    masked: str  # comments and string contents replaced by spaces
    masked_np: str  # additionally preprocessor lines blanked
    functions: list
    includes: list
    globals: dict
    comments: list  # list of (line, text)
    line_starts: list

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, offset)

    def line_text(self, line: int) -> str:
        lines = self.source.splitlines()
        return lines[line - 1] if 1 <= line <= len(lines) else ""

    def function_at(self, line: int):
        for fn in self.functions:
            if fn.start_line <= line <= fn.end_line:
                return fn
        return None


def mask_source(src: str) -> tuple[str, list]:
    """Replace comments and string/char literal contents with spaces (keeping newlines and offsets)."""
    out = list(src)
    comments = []
    i, n = 0, len(src)
    line = 1
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if ch == "\n":
            line += 1
            i += 1
        elif ch == "/" and nxt == "/":
            start, start_line = i, line
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            comments.append((start_line, src[start + 2:i].strip()))
        elif ch == "/" and nxt == "*":
            start, start_line = i, line
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                i += 1
            end = min(i + 2, n)
            for k in range(start, end):
                if src[k] == "\n":
                    line += 1
                else:
                    out[k] = " "
            comments.append((start_line, src[start + 2:end - 2].strip(" *\n")))
            i = end
        elif ch in ("'", '"'):
            quote = ch
            i += 1
            while i < n and src[i] != quote and src[i] != "\n":
                if src[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    i += 1
                out[i] = " "
                i += 1
            i += 1
        else:
            i += 1
    return "".join(out), comments


def blank_preprocessor(masked: str) -> str:
    lines = masked.split("\n")
    continuing = False
    for idx, ln in enumerate(lines):
        if continuing or ln.lstrip().startswith("#"):
            continuing = ln.rstrip().endswith("\\")
            lines[idx] = " " * len(ln)
    return "\n".join(lines)


def split_args(text: str) -> list[str]:
    """Split a comma separated argument list respecting nested parentheses/brackets."""
    args, depth, cur = [], 0, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def matching_paren(text: str, open_idx: int, open_ch: str = "(", close_ch: str = ")") -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return -1


def _parse_params(param_text: str) -> list:
    params = []
    for p in split_args(param_text):
        p = " ".join(p.split())
        if not p or p == "void" or p == "...":
            continue
        m = re.search(rf"({IDENT})\s*(\[[^\]]*\])?\s*$", p)
        if not m:
            continue
        name = m.group(1)
        ptype = p[: m.start(1)].strip()
        if not ptype:  # K&R or type-only parameter
            continue
        params.append({"type": ptype, "name": name, "pointer": "*" in ptype or bool(m.group(2))})
    return params


def compute_metrics(masked_body: str, params: list) -> dict:
    body = masked_body
    decisions = len(re.findall(r"\b(if|for|while|case)\b", body)) + body.count("&&") + body.count("||")
    decisions += len(re.findall(r"\?(?!\?)", body))
    depth = max_depth = 0
    for ch in body:
        if ch == "{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == "}":
            depth -= 1
    lines = [ln for ln in body.split("\n") if ln.strip() and ln.strip() not in ("{", "}")]
    return {
        "loc": len(lines),
        "cyclomatic": 1 + decisions,
        "nesting": max(0, max_depth - 1),
        "params": len(params),
        "pointer_params": sum(1 for p in params if p["pointer"]),
        "memory_accesses": body.count("->") + body.count("["),
        "calls": len([c for c in re.findall(rf"\b({IDENT})\s*\(", body) if c not in NON_CALLS]),
        "returns": len(re.findall(r"\breturn\b", body)),
        "gotos": len(re.findall(r"\bgoto\b", body)),
        "loops": len(re.findall(r"\b(for|while)\b", body)),
        "branches": len(re.findall(r"\b(if|case)\b", body)),
        "dyn_alloc": len(re.findall(r"\b(malloc|calloc|realloc|free)\s*\(", body)),
    }


GLOBAL_RE = re.compile(
    rf"^\s*(?P<quals>(?:(?:static|volatile|const|extern)\s+)*)"
    rf"(?P<type>(?:unsigned\s+|signed\s+)?{IDENT})(?:\s*(?P<ptr>\*+)\s*|\s+)"
    rf"(?P<quals2>(?:(?:volatile|const)\s+)*)(?P<name>{IDENT})\s*(?P<arr>\[[^\]]*\])?\s*(?:=.*)?$",
    re.S,
)


def parse_c(path: str, source: str) -> ParsedFile:
    source = source.replace("\r\n", "\n")
    masked, comments = mask_source(source)
    masked_np = blank_preprocessor(masked)
    line_starts = [0] + [m.end() for m in re.finditer("\n", source)]

    def line_of(off: int) -> int:
        return bisect.bisect_right(line_starts, off)

    includes = re.findall(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', source, re.M)

    functions, statements = [], []
    depth, seg_start, cand, initializer = 0, 0, None, False
    for i, ch in enumerate(masked_np):
        if ch == "{":
            if depth == 0:
                header = masked_np[seg_start:i]
                initializer = "=" in header
                m = re.search(rf"({IDENT})\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*$", header)
                cand = None
                if m and not initializer and m.group(1) not in CONTROL_KEYWORDS:
                    ret = " ".join(header[: m.start(1)].split())
                    if ret and not ret.endswith((",", "(")) and "typedef" not in ret:
                        cand = (m, ret, seg_start, i)
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                if cand:
                    m, ret, hstart, bstart = cand
                    name = m.group(1)
                    params = _parse_params(m.group(2))
                    body = source[bstart:i + 1]
                    mbody = masked[bstart:i + 1]
                    metrics = compute_metrics(mbody, params)
                    calls = sorted({c for c in re.findall(rf"\b({IDENT})\s*\(", mbody) if c not in NON_CALLS})
                    sig_start = hstart + len(masked_np[hstart:bstart]) - len(masked_np[hstart:bstart].lstrip())
                    functions.append(FunctionInfo(
                        name=name, return_type=ret, params=params,
                        signature=" ".join(source[sig_start:bstart].split()),
                        start_line=line_of(sig_start), end_line=line_of(i),
                        body_start=bstart, body_end=i, body=body, masked_body=mbody,
                        metrics=metrics, calls=calls,
                    ))
                    cand = None
                if not initializer:
                    seg_start = i + 1
        elif ch == ";" and depth == 0:
            statements.append((seg_start, masked_np[seg_start:i]))
            seg_start = i + 1
            initializer = False

    globals_ = {}
    for off, stmt in statements:
        text = stmt.strip()
        if not text or text.startswith(("typedef", "struct", "enum", "union")) or "(" in text:
            continue
        m = GLOBAL_RE.match(text)
        if not m:
            continue
        quals = (m.group("quals") or "") + (m.group("quals2") or "")
        name = m.group("name")
        globals_[name] = {
            "type": m.group("type"),
            "static": "static" in quals,
            "volatile": "volatile" in quals,
            "const": "const" in quals,
            "extern": "extern" in quals,
            "array": (m.group("arr") or "").strip("[] ") or None,
            "line": line_of(off + stmt.find(name)),
        }

    return ParsedFile(
        path=path, source=source, masked=masked, masked_np=masked_np, functions=functions,
        includes=includes, globals=globals_, comments=comments, line_starts=line_starts,
    )


def summarize_function(fn: FunctionInfo, findings: list | None = None) -> str:
    """Plain-English control-flow/dependency summary built from parser facts (no LLM needed)."""
    m = fn.metrics
    params = ", ".join(f"{p['name']} ({p['type']})" for p in fn.params) or "no parameters"
    parts = [f"`{fn.name}` returns `{fn.return_type}` and takes {params}."]
    flow = []
    if m["branches"]:
        flow.append(f"{m['branches']} decision point{'s' if m['branches'] != 1 else ''}")
    if m["loops"]:
        flow.append(f"{m['loops']} loop{'s' if m['loops'] != 1 else ''}")
    flow.append(f"{m['returns']} exit point{'s' if m['returns'] != 1 else ''}")
    parts.append(f"Control flow: {', '.join(flow)}; cyclomatic complexity {m['cyclomatic']}, max nesting {m['nesting']}.")
    if fn.calls:
        shown = ", ".join(f"`{c}`" for c in fn.calls[:8])
        more = f" and {len(fn.calls) - 8} more" if len(fn.calls) > 8 else ""
        parts.append(f"It calls {shown}{more}.")
    if m["dyn_alloc"]:
        parts.append("It uses dynamic memory.")
    if findings:
        parts.append(f"{len(findings)} review finding(s) are linked to this function.")
    return " ".join(parts)
