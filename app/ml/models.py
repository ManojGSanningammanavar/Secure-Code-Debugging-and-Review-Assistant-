"""The five ML models used by ECU Sentinel, plus a registry that trains, saves and loads them.

1. DefectClassifier    - TF-IDF (C tokens + char n-grams) + Logistic Regression -> defect class per function
2. TriageModel         - Gradient Boosting on finding features -> probability a reviewer accepts the finding
3. LogClassifier       - TF-IDF + Logistic Regression -> category of compiler/static-analysis warnings
                         (+ agglomerative clustering of warnings into root-cause groups)
4. InjectionDetector   - TF-IDF word+char + Logistic Regression -> prompt-injection likelihood of repo text
5. ComplexityAnomaly   - StandardScaler + Isolation Forest on function metrics -> hotspot score
"""
import json
import math
import threading
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.cluster import AgglomerativeClustering
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

from .. import config
from ..analysis.c_parser import mask_source, parse_c
from ..analysis.log_parser import normalise_message
from . import dataset

C_TOKEN_PATTERN = r"[A-Za-z_]\w*|==|!=|<=|>=|->|&&|\|\||\+\+|--|[{}()\[\];,<>=+\-*/%!&|]"
METRIC_KEYS = ["loc", "cyclomatic", "nesting", "params", "pointer_params", "memory_accesses", "calls", "returns",
               "gotos", "loops", "branches", "dyn_alloc"]


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _code_text(code: str) -> str:
    return mask_source(code)[0]


# ============================================================ 1. defect classifier
class DefectClassifier:
    name = "defect_classifier"

    def __init__(self):
        self.pipeline = None
        self.metrics = {}

    @staticmethod
    def _build():
        features = FeatureUnion([
            ("tokens", TfidfVectorizer(token_pattern=C_TOKEN_PATTERN, ngram_range=(1, 3), lowercase=False,
                                       min_df=2, sublinear_tf=True, max_features=30000)),
            ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True,
                                      max_features=30000)),
        ])
        return Pipeline([("features", features),
                         ("clf", LogisticRegression(max_iter=3000, C=6.0, class_weight="balanced"))])

    def fit(self, codes: list[str], labels: list[str]):
        texts = [_code_text(c) for c in codes]
        Xtr, Xte, ytr, yte = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
        pred = self._build().fit(Xtr, ytr).predict(Xte)
        classes = sorted(set(labels))
        self.metrics = {
            "accuracy": round(accuracy_score(yte, pred), 4),
            "macro_f1": round(f1_score(yte, pred, average="macro"), 4),
            "per_class_f1": {c: round(float(s), 3) for c, s in zip(classes, f1_score(yte, pred, average=None, labels=classes))},
            "train_samples": len(Xtr), "test_samples": len(Xte), "trained_at": _now(),
            "algorithm": "TF-IDF (C tokens 1-3 + char 3-5) + Logistic Regression",
        }
        self.pipeline = self._build().fit(texts, labels)
        return self

    def predict(self, codes: list[str]) -> list[dict]:
        if not codes:
            return []
        probs = self.pipeline.predict_proba([_code_text(c) for c in codes])
        classes = list(self.pipeline.classes_)
        out = []
        for p in probs:
            i = int(np.argmax(p))
            out.append({"label": classes[i], "confidence": float(p[i]), "probs": {c: float(v) for c, v in zip(classes, p)}})
        return out


# ============================================================ 2. triage model
class TriageModel:
    name = "triage_model"

    def __init__(self):
        self.vec = None
        self.clf = None
        self.metrics = {}

    @staticmethod
    def _clf():
        return GradientBoostingClassifier(n_estimators=160, max_depth=3, learning_rate=0.08, random_state=42)

    def fit(self, rows: list[dict], labels: list[int], real_samples: int = 0):
        Xtr, Xte, ytr, yte = train_test_split(rows, labels, test_size=0.2, random_state=42, stratify=labels)
        vec = DictVectorizer(sparse=False)
        clf = self._clf().fit(vec.fit_transform(Xtr), ytr)
        proba = clf.predict_proba(vec.transform(Xte))[:, 1]
        pred = (proba >= 0.5).astype(int)
        self.metrics = {
            "roc_auc": round(roc_auc_score(yte, proba), 4), "accuracy": round(accuracy_score(yte, pred), 4),
            "precision": round(precision_score(yte, pred, zero_division=0), 4),
            "recall": round(recall_score(yte, pred, zero_division=0), 4),
            "train_samples": len(Xtr), "test_samples": len(Xte), "reviewer_labels": real_samples,
            "trained_at": _now(), "algorithm": "DictVectorizer + Gradient Boosting (160 trees, depth 3)",
        }
        self.vec = DictVectorizer(sparse=False)
        self.clf = self._clf().fit(self.vec.fit_transform(rows), labels)
        return self

    def predict(self, rows: list[dict]) -> list[float]:
        if not rows:
            return []
        return [float(p) for p in self.clf.predict_proba(self.vec.transform(rows))[:, 1]]


# ============================================================ 3. log classifier + clustering
class LogClassifier:
    name = "log_classifier"

    def __init__(self):
        self.pipeline = None
        self.metrics = {}

    @staticmethod
    def _build():
        return Pipeline([
            ("features", FeatureUnion([
                ("words", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, token_pattern=r"[A-Za-z_\-=]+")),
                ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)),
            ])),
            ("clf", LogisticRegression(max_iter=3000, C=5.0, class_weight="balanced")),
        ])

    def fit(self, messages, labels):
        texts = [normalise_message(m) for m in messages]
        Xtr, Xte, ytr, yte = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
        pred = self._build().fit(Xtr, ytr).predict(Xte)
        self.metrics = {"accuracy": round(accuracy_score(yte, pred), 4), "macro_f1": round(f1_score(yte, pred, average="macro"), 4),
                        "train_samples": len(Xtr), "test_samples": len(Xte), "trained_at": _now(),
                        "algorithm": "TF-IDF (word 1-2 + char 3-5) + Logistic Regression; Agglomerative clustering (cosine)"}
        self.pipeline = self._build().fit(texts, labels)
        return self

    def predict(self, messages: list[str]) -> list[dict]:
        if not messages:
            return []
        probs = self.pipeline.predict_proba([normalise_message(m) for m in messages])
        classes = list(self.pipeline.classes_)
        return [{"label": classes[int(np.argmax(p))], "confidence": float(np.max(p))} for p in probs]

    @staticmethod
    def cluster(messages: list[str], labels: list[str] | None = None, threshold: float = 0.9) -> list[int]:
        """Root-cause grouping: warnings are first grouped by predicted category, then split with
        agglomerative clustering (cosine, average linkage) so unrelated messages stay apart."""
        if not messages:
            return []
        labels = labels or ["all"] * len(messages)
        texts = [normalise_message(m) for m in messages]
        out, next_id = [0] * len(messages), 0
        for cat in dict.fromkeys(labels):
            idx = [i for i, lab in enumerate(labels) if lab == cat]
            if len(idx) == 1:
                out[idx[0]] = next_id
                next_id += 1
                continue
            X = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 4)).fit_transform([texts[i] for i in idx]).toarray()
            X[~X.any(axis=1)] = 1e-6
            sub = AgglomerativeClustering(n_clusters=None, distance_threshold=threshold, metric="cosine",
                                          linkage="average").fit_predict(X)
            remap = {}
            for i, c in zip(idx, sub):
                if c not in remap:
                    remap[c] = next_id
                    next_id += 1
                out[i] = remap[c]
        return out


# ============================================================ 4. injection detector
class InjectionDetector:
    name = "injection_detector"

    def __init__(self):
        self.pipeline = None
        self.metrics = {}

    @staticmethod
    def _build():
        return Pipeline([
            ("features", FeatureUnion([
                ("words", TfidfVectorizer(ngram_range=(1, 3), sublinear_tf=True, lowercase=True)),
                ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)),
            ])),
            ("clf", LogisticRegression(max_iter=3000, C=3.0)),
        ])

    def fit(self, texts, labels):
        Xtr, Xte, ytr, yte = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
        proba = self._build().fit(Xtr, ytr).predict_proba(Xte)[:, 1]
        self.metrics = {"roc_auc": round(roc_auc_score(yte, proba), 4), "accuracy": round(accuracy_score(yte, proba >= 0.5), 4),
                        "train_samples": len(Xtr), "test_samples": len(Xte), "trained_at": _now(),
                        "algorithm": "TF-IDF (word 1-3 + char 2-5) + Logistic Regression"}
        self.pipeline = self._build().fit(texts, labels)
        return self

    def score(self, texts: list[str]) -> list[float]:
        if not texts:
            return []
        return [float(p) for p in self.pipeline.predict_proba(texts)[:, 1]]


# ============================================================ 5. complexity anomaly
class ComplexityAnomaly:
    name = "complexity_anomaly"

    def __init__(self):
        self.scaler = None
        self.forest = None
        self.metrics = {}

    @staticmethod
    def vectorize(metrics_list: list[dict]) -> np.ndarray:
        return np.array([[math.log1p(m.get(k, 0)) for k in METRIC_KEYS] for m in metrics_list], dtype=float)

    def fit(self, metrics_list: list[dict]):
        X = self.vectorize(metrics_list)
        self.scaler = StandardScaler().fit(X)
        self.forest = IsolationForest(n_estimators=200, contamination=0.05, random_state=42).fit(self.scaler.transform(X))
        flagged = int((self.forest.predict(self.scaler.transform(X)) == -1).sum())
        self.metrics = {"reference_functions": len(metrics_list), "flagged_in_reference": flagged, "trained_at": _now(),
                        "algorithm": "StandardScaler + Isolation Forest (200 trees) on 12 code metrics, fused with per-repo fit"}
        return self

    def score(self, metrics_list: list[dict]) -> list[float]:
        if not metrics_list:
            return []
        X = self.vectorize(metrics_list)
        ref = self.forest.decision_function(self.scaler.transform(X))
        scores = 1 / (1 + np.exp(12 * ref))  # negative decision -> anomalous -> score near 1
        if len(metrics_list) >= 8:  # blend with a repository-local model so hotspots are relative to the codebase
            sc = StandardScaler().fit(X)
            local = IsolationForest(n_estimators=150, contamination="auto", random_state=7).fit(sc.transform(X))
            loc_scores = 1 / (1 + np.exp(12 * local.decision_function(sc.transform(X))))
            scores = 0.5 * scores + 0.5 * loc_scores
        return [round(float(s), 4) for s in scores]


# ============================================================ registry
class ModelRegistry:
    def __init__(self):
        self.defect = DefectClassifier()
        self.triage = TriageModel()
        self.logs = LogClassifier()
        self.injection = InjectionDetector()
        self.anomaly = ComplexityAnomaly()

    @property
    def models(self):
        return [self.defect, self.triage, self.logs, self.injection, self.anomaly]

    def train_all(self) -> dict:
        codes, labels = dataset.make_defect_corpus()
        self.defect.fit(codes, labels)
        self.train_triage()
        self.logs.fit(*dataset.make_log_corpus())
        self.injection.fit(*dataset.make_injection_corpus())
        ref_metrics = []
        for c in codes:
            ref_metrics += [fn.metrics for fn in parse_c("synthetic.c", c).functions]
        self.anomaly.fit(ref_metrics)
        self.save()
        return self.metrics()

    def train_triage(self, extra: tuple | None = None) -> dict:
        rows, labels = dataset.make_triage_history()
        real = 0
        if extra and extra[0]:
            # reviewer decisions are weighted x5 by replication so the model adapts quickly
            rows = rows + extra[0] * 5
            labels = labels + extra[1] * 5
            real = len(extra[0])
        self.triage.fit(rows, labels, real_samples=real)
        return self.triage.metrics

    def save(self):
        config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
        for m in self.models:
            joblib.dump(m, config.MODEL_DIR / f"{m.name}.joblib")
        (config.MODEL_DIR / "metrics.json").write_text(json.dumps(self.metrics(), indent=2))

    def load(self) -> bool:
        try:
            self.defect = joblib.load(config.MODEL_DIR / "defect_classifier.joblib")
            self.triage = joblib.load(config.MODEL_DIR / "triage_model.joblib")
            self.logs = joblib.load(config.MODEL_DIR / "log_classifier.joblib")
            self.injection = joblib.load(config.MODEL_DIR / "injection_detector.joblib")
            self.anomaly = joblib.load(config.MODEL_DIR / "complexity_anomaly.joblib")
            return True
        except (FileNotFoundError, EOFError, AttributeError, ModuleNotFoundError):
            return False

    def metrics(self) -> dict:
        return {m.name: m.metrics for m in self.models}


_registry: ModelRegistry | None = None
_lock = threading.Lock()


def get_registry() -> ModelRegistry:
    global _registry
    with _lock:
        if _registry is None:
            reg = ModelRegistry()
            if not reg.load():
                reg.train_all()
            _registry = reg
        return _registry
