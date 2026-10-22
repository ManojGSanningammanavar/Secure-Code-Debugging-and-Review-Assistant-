"""Parse compiler (GCC/Clang), cppcheck and linker output into structured warnings."""
import re

GCC_RE = re.compile(
    r"^(?P<file>[^\s:][^:]*?\.(?:c|h|cpp|hpp|cc)):(?P<line>\d+):(?:(?P<col>\d+):)?\s*"
    r"(?P<level>fatal error|error|warning|note|remark)\s*:\s*(?P<msg>.+)$"
)
CPPCHECK_RE = re.compile(r"^\[(?P<file>[^:\]]+):(?P<line>\d+)\](?::\d+)?:?\s*\((?P<level>\w+)\)\s*(?P<msg>.+)$")
LINKER_RE = re.compile(r"(?P<msg>(undefined reference to|multiple definition of|cannot find -l)\s*.+)$")
FLAG_RE = re.compile(r"\[(-W[\w=\-+]+|[\w\-]+\.[\w\-]+)\]\s*$")


def normalise_path(path: str) -> str:
    p = path.replace("\\", "/")
    for marker in ("/src/", "/include/", "/inc/"):
        if marker in p:
            return p[p.rfind(marker) + 1:]
    return p.lstrip("./")


def parse_log(text: str) -> list[dict]:
    warnings = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        m = GCC_RE.match(line) or CPPCHECK_RE.match(line)
        if m:
            level = m.group("level").lower()
            if level == "note":
                continue
            msg = m.group("msg").strip()
            flag = FLAG_RE.search(msg)
            warnings.append({
                "log_line": idx,
                "file": normalise_path(m.group("file")),
                "line": int(m.group("line")),
                "level": "error" if "error" in level else ("warning" if level in ("warning", "style", "performance", "portability") else level),
                "tool": "cppcheck" if line.startswith("[") else "compiler",
                "flag": flag.group(1) if flag else "",
                "message": FLAG_RE.sub("", msg).strip(),
            })
            continue
        lm = LINKER_RE.search(line)
        if lm:
            warnings.append({"log_line": idx, "file": "", "line": 0, "level": "error", "tool": "linker",
                             "flag": "", "message": lm.group("msg").strip()})
    return warnings


def normalise_message(msg: str) -> str:
    """Template a message so that similar warnings cluster together."""
    msg = re.sub(r"'[^']*'|‘[^’]*’|`[^']*'", " QID ", msg)
    msg = re.sub(r"\b0x[0-9a-fA-F]+\b|\b\d+\b", " NUM ", msg)
    return " ".join(msg.split()).lower()
