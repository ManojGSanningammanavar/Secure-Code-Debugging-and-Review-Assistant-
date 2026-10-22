"""Hybrid retrieval (BM25 lexical + dense semantic vectors) over code chunks and internal guidelines.

Dense vectors default to LSA (TF-IDF + TruncatedSVD), which needs no model download and runs
fully offline. Set EMBEDDING_BACKEND=sentence-transformers to use BGE/E5 models if installed.
Indexes are persisted per repository under var/index.
"""
import math
import re
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize

from .. import config

STOPWORDS = set("""a an and are as at be by can could do does did for from has have how i if in into is it its me my
not of on or our should so that the their them then there these this to was we were what when where which who why will
with would you your about tell explain""".split())
GUIDELINE_INTENT = re.compile(r"\b(why|rule|rules|guideline|standard|misra|cwe|allowed|forbidden|policy|permitted|best practice|recommend\w*)\b", re.I)
C_API = {"strcpy", "strncpy", "strcat", "sprintf", "snprintf", "vsprintf", "gets", "memcpy", "memmove", "memset", "malloc",
         "calloc", "realloc", "free", "printf", "fprintf", "scanf", "atoi", "atol", "atof", "fopen", "fclose", "goto",
         "volatile", "switch", "default", "isr", "interrupt", "null"}
SYNONYMS = {"allowed": ["forbidden", "permitted"], "banned": ["forbidden"], "unsafe": ["unbounded", "forbidden"],
            "crash": ["null", "overflow"], "leak": ["release", "resource"], "race": ["interrupt", "shared"],
            "key": ["secret", "keys"], "password": ["secret", "credentials"], "injection": ["prompt", "untrusted"]}


def tokenize(text: str) -> list[str]:
    """Identifier-aware tokenizer: Brake_ComputePressure -> brake_computepressure, brake, compute, pressure."""
    tokens = []
    for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?", text):
        low = raw.lower()
        if low in STOPWORDS:
            continue
        tokens.append(low)
        parts = [p for p in re.split(r"_|(?<=[a-z0-9])(?=[A-Z])", raw) if p]
        if len(parts) > 1:
            tokens += [p.lower() for p in parts if len(p) > 1]
    return tokens


def expand_query(query: str) -> list[str]:
    """Query-side weighting: C API names count double; a few domain synonyms are added."""
    tokens = tokenize(query)
    extra = []
    for t in tokens:
        if t in C_API:
            extra.append(t)
        extra += SYNONYMS.get(t, [])
    return tokens + extra


class BM25:
    def __init__(self, docs_tokens: list[list[str]], k1: float = 1.4, b: float = 0.5):
        self.k1, self.b = k1, b
        self.docs = [Counter(t) for t in docs_tokens]
        self.lens = [len(t) for t in docs_tokens]
        self.avg = (sum(self.lens) / len(self.lens)) if self.lens else 1.0
        df = Counter()
        for d in self.docs:
            df.update(d.keys())
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def scores(self, query_tokens: list[str]) -> np.ndarray:
        out = np.zeros(len(self.docs))
        weights = Counter(query_tokens)  # repeated query tokens carry more weight
        for i, d in enumerate(self.docs):
            s = 0.0
            for t, w in weights.items():
                if t in d:
                    tf = d[t]
                    s += w * self.idf.get(t, 0) * tf * (self.k1 + 1) / (tf + self.k1 * (1 - self.b + self.b * self.lens[i] / self.avg))
            out[i] = s
        return out


class DenseEncoder:
    def __init__(self):
        self.backend = "lsa"
        self.vectorizer = None
        self.svd = None
        self.st_model = None

    def fit(self, texts: list[str]):
        if config.EMBEDDING_BACKEND == "sentence-transformers":
            try:
                from sentence_transformers import SentenceTransformer  # optional dependency
                self.st_model = SentenceTransformer(config.EMBEDDING_MODEL)
                self.backend = "sentence-transformers"
                return self
            except Exception:  # fall back to LSA if unavailable
                self.st_model = None
        self.backend = "lsa"
        self.vectorizer = TfidfVectorizer(tokenizer=tokenize, lowercase=False, token_pattern=None, sublinear_tf=True)
        X = self.vectorizer.fit_transform(texts)
        n_comp = max(2, min(128, X.shape[0] - 1, X.shape[1] - 1))
        self.svd = TruncatedSVD(n_components=n_comp, random_state=42).fit(X)
        return self

    def encode(self, texts: list[str]) -> np.ndarray:
        if self.st_model is not None:
            return np.asarray(self.st_model.encode(texts, normalize_embeddings=True))
        return normalize(self.svd.transform(self.vectorizer.transform(texts)))

    def __getstate__(self):  # never pickle the transformer itself
        state = dict(self.__dict__)
        state["st_model"] = None
        return state


class HybridIndex:
    def __init__(self, docs: list[dict]):
        self.docs = docs
        self.texts = [f"{d.get('title', '')}\n{d['text']}" for d in docs]
        self.bm25 = BM25([tokenize(t) for t in self.texts])
        self.encoder = DenseEncoder().fit(self.texts)
        self.vectors = self.encoder.encode(self.texts)

    def search(self, query: str, k: int = 6, kinds: set | None = None, allow=None) -> list[dict]:
        if not self.docs:
            return []
        if self.encoder.backend == "sentence-transformers" and self.encoder.st_model is None:
            self.encoder.fit(self.texts)  # reload transformer after unpickling
        lex = self.bm25.scores(expand_query(query))
        dense = self.vectors @ self.encoder.encode([query])[0]
        lex_rank = {i: r for r, i in enumerate(np.argsort(-lex))}
        dense_rank = {i: r for r, i in enumerate(np.argsort(-dense))}
        policy_intent = bool(GUIDELINE_INTENT.search(query))
        fused = []
        for i, d in enumerate(self.docs):
            if kinds and d["kind"] not in kinds:
                continue
            if allow and not allow(d):
                continue
            if lex[i] <= 0 and dense[i] < 0.05:
                continue
            score = 1.0 / (20 + lex_rank[i]) + 0.7 / (20 + dense_rank[i])  # weighted reciprocal-rank fusion
            if policy_intent and d["kind"] == "guideline":
                score *= 1.25  # policy-style questions prefer approved guidance over code
            fused.append((score, i))
        fused.sort(reverse=True)
        results = []
        for score, i in fused[:k]:
            d = dict(self.docs[i])
            d.update(score=round(score * 1000, 3), lexical=round(float(lex[i]), 3), semantic=round(float(dense[i]), 3))
            results.append(d)
        return results


# ------------------------------------------------------------------ document builders
def guideline_docs() -> list[dict]:
    docs = []
    for path in sorted(Path(config.GUIDELINES_DIR).glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for block in re.split(r"\n(?=## )", text):
            block = block.strip()
            if not block.startswith("## "):
                continue
            title = block.splitlines()[0][3:].strip()
            gid = re.match(r"([A-Z]+-[A-Z]+-\d+)", title)
            docs.append({"id": f"guide:{path.name}:{title}", "kind": "guideline", "title": title, "text": block,
                         "path": f"guidelines/{path.name}", "guideline_id": gid.group(1) if gid else "",
                         "start_line": 0, "end_line": 0})
    return docs


def code_docs(parsed_files) -> list[dict]:
    docs = []
    for pf in parsed_files:
        lines = pf.source.splitlines()
        header_end = pf.functions[0].start_line - 1 if pf.functions else min(40, len(lines))
        header = "\n".join(lines[:max(header_end, 1)])
        docs.append({"id": f"code:{pf.path}:header", "kind": "code", "title": f"{pf.path} (module header)",
                     "text": header[:3000], "path": pf.path, "function": None, "start_line": 1, "end_line": max(header_end, 1)})
        for fn in pf.functions:
            start = fn.start_line
            while start > 1 and lines[start - 2].strip().startswith(("/*", "*", "//")):
                start -= 1  # attach the leading doc comment so it travels (and is screened) with the function
            text = "\n".join(lines[start - 1:fn.end_line])
            docs.append({"id": f"code:{pf.path}:{fn.name}", "kind": "code", "title": f"{pf.path} › {fn.name}()",
                         "text": text[:4000], "path": pf.path, "function": fn.name,
                         "start_line": fn.start_line, "end_line": fn.end_line})
    return docs


_cache: dict = {}


def build_index(repo_id: int, parsed_files) -> HybridIndex:
    idx = HybridIndex(code_docs(parsed_files) + guideline_docs())
    config.INDEX_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(idx, config.INDEX_DIR / f"repo_{repo_id}.joblib")
    _cache[repo_id] = idx
    return idx


def load_index(repo_id: int) -> HybridIndex | None:
    if repo_id in _cache:
        return _cache[repo_id]
    path = config.INDEX_DIR / f"repo_{repo_id}.joblib"
    if path.exists():
        try:
            _cache[repo_id] = joblib.load(path)
            return _cache[repo_id]
        except Exception:
            return None
    return None


def invalidate(repo_id: int) -> None:
    _cache.pop(repo_id, None)
    path = config.INDEX_DIR / f"repo_{repo_id}.joblib"
    if path.exists():
        path.unlink()
