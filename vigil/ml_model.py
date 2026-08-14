"""
VIGIL behavioural anomaly model — real scikit-learn IsolationForest.

The paper (Section 4.1, Algorithm 1) specifies that VIGIL scores endpoint
telemetry with an ``IsolationForest`` ensemble over four Indicators of Behaviour
(IoB), with ``contamination=0.02`` and ``n_estimators=200``. Earlier revisions of
this repository declared scikit-learn as a dependency but never imported it and
scored threats with hard-coded thresholds instead. This module implements the
model the paper describes.

Feature vector (order matters — see ``FEATURES``):
    0. file_rename_rate          renames/sec, per-host baseline-normalised
    1. lateral_movement_score    novel SMB auth attempts to new peers
    2. privilege_escalation      token-impersonation / LSASS / Kerberoast count
    3. shadow_copy_deletion_rate vssadmin/Remove-Item shadow deletions

The model exposes a bounded anomaly score in [0, 1] (1 = most anomalous) via a
logistic squashing of IsolationForest's ``score_samples`` output, and a decision
threshold ``theta`` (paper default 0.85).

If scikit-learn is unavailable at runtime the class degrades gracefully to a
robust z-score heuristic over the same features, so importing this module never
fails and the detection path always has a scorer. Callers can check
``model.backend`` to know which is active.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)

FEATURES = [
    "file_rename_rate",
    "lateral_movement_score",
    "privilege_escalation",
    "shadow_copy_deletion_rate",
]

DEFAULT_THRESHOLD = 0.85          # theta
DEFAULT_CONTAMINATION = 0.02      # targets <= 2% false positive rate
DEFAULT_N_ESTIMATORS = 200
_MODEL_ENV = "VIGIL_MODEL_PATH"


@dataclass
class IoBVector:
    """A single Indicator-of-Behaviour feature vector."""

    file_rename_rate: float = 0.0
    lateral_movement_score: float = 0.0
    privilege_escalation: float = 0.0
    shadow_copy_deletion_rate: float = 0.0

    def as_list(self) -> List[float]:
        return [
            self.file_rename_rate,
            self.lateral_movement_score,
            self.privilege_escalation,
            self.shadow_copy_deletion_rate,
        ]

    @classmethod
    def from_mapping(cls, m: dict) -> "IoBVector":
        return cls(**{k: float(m.get(k, 0.0)) for k in FEATURES})


@dataclass
class Detection:
    anomaly_score: float          # [0, 1]
    is_anomaly: bool
    threshold: float
    contributing_features: List[str]
    backend: str


class VigilAnomalyModel:
    """IsolationForest-based behavioural anomaly detector (with heuristic fallback)."""

    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        contamination: float = DEFAULT_CONTAMINATION,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        random_state: int = 42,
    ) -> None:
        self.threshold = threshold
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self._model = None            # sklearn estimator once fitted
        self._scaler = None
        self._fallback_stats = None   # (median, mad) per feature for heuristic
        self.backend = "unfitted"

    # -- training -------------------------------------------------------------
    def train(self, benign_samples: Sequence[Sequence[float]]) -> "VigilAnomalyModel":
        """
        Fit the model on a benign behavioural baseline (paper: 30-day per-host
        baseline). ``benign_samples`` is an array-like of shape (n, 4).
        """
        X = [list(map(float, row)) for row in benign_samples]
        if not X:
            raise ValueError("training set is empty")

        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler

            arr = np.asarray(X, dtype=float)
            self._scaler = StandardScaler().fit(arr)
            scaled = self._scaler.transform(arr)
            self._model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=-1,
            ).fit(scaled)
            # Calibrate the logistic squashing against the training distribution
            raw = self._model.score_samples(scaled)
            self._raw_mean = float(np.mean(raw))
            self._raw_std = float(np.std(raw)) or 1.0
            self.backend = "isolation_forest"
            logger.info(
                "VIGIL model trained: IsolationForest(n_estimators=%d, contamination=%.3f) on %d samples",
                self.n_estimators, self.contamination, len(X),
            )
        except Exception as exc:  # pragma: no cover - depends on runtime env
            logger.warning("scikit-learn unavailable (%s); using z-score fallback detector", exc)
            self._fit_fallback(X)
        return self

    def _fit_fallback(self, X: Sequence[Sequence[float]]) -> None:
        cols = list(zip(*X))
        stats = []
        for col in cols:
            s = sorted(col)
            median = s[len(s) // 2]
            mad = sorted(abs(v - median) for v in col)[len(col) // 2] or 1e-6
            stats.append((median, mad))
        self._fallback_stats = stats
        self.backend = "zscore_fallback"

    # -- scoring --------------------------------------------------------------
    def score(self, features) -> Detection:
        vec = features.as_list() if isinstance(features, IoBVector) else list(map(float, features))
        if len(vec) != len(FEATURES):
            raise ValueError(f"expected {len(FEATURES)} features, got {len(vec)}")

        if self.backend == "isolation_forest":
            score = self._score_iforest(vec)
        elif self.backend == "zscore_fallback":
            score = self._score_fallback(vec)
        else:
            raise RuntimeError("model is not trained; call train() first")

        contributing = self._contributing_features(vec)
        return Detection(
            anomaly_score=round(score, 4),
            is_anomaly=score >= self.threshold,
            threshold=self.threshold,
            contributing_features=contributing,
            backend=self.backend,
        )

    def _score_iforest(self, vec: List[float]) -> float:
        import numpy as np

        scaled = self._scaler.transform(np.asarray([vec], dtype=float))
        raw = float(self._model.score_samples(scaled)[0])
        # Lower score_samples == more anomalous. Convert to a z-distance below
        # the benign mean and squash to [0, 1] with a logistic.
        z = (self._raw_mean - raw) / self._raw_std
        return 1.0 / (1.0 + pow(2.718281828, -1.5 * z))

    def _score_fallback(self, vec: List[float]) -> float:
        worst = 0.0
        for value, (median, mad) in zip(vec, self._fallback_stats):
            z = abs(value - median) / (1.4826 * mad)
            worst = max(worst, z)
        # Map a robust z-score to [0, 1]; z>=4 ~ score 1.
        return min(1.0, worst / 4.0)

    def _contributing_features(self, vec: List[float]) -> List[str]:
        """Rank features by relative magnitude for explainability."""
        if self._fallback_stats:
            scored = []
            for name, value, (median, mad) in zip(FEATURES, vec, self._fallback_stats):
                scored.append((name, abs(value - median) / (1.4826 * mad)))
        else:
            scored = [(name, value) for name, value in zip(FEATURES, vec)]
        scored.sort(key=lambda t: t[1], reverse=True)
        return [name for name, weight in scored if weight > 0][:3]

    # -- persistence ----------------------------------------------------------
    def save(self, path: str) -> None:
        if self.backend != "isolation_forest":
            logger.warning("save() is a no-op for backend=%s", self.backend)
            return
        try:
            import joblib

            joblib.dump(
                {
                    "model": self._model,
                    "scaler": self._scaler,
                    "threshold": self.threshold,
                    "raw_mean": self._raw_mean,
                    "raw_std": self._raw_std,
                },
                path,
            )
            logger.info("VIGIL model persisted to %s", path)
        except Exception as exc:  # pragma: no cover
            logger.error("failed to persist model: %s", exc)

    @classmethod
    def load(cls, path: str) -> Optional["VigilAnomalyModel"]:
        try:
            import joblib

            blob = joblib.load(path)
            inst = cls(threshold=blob.get("threshold", DEFAULT_THRESHOLD))
            inst._model = blob["model"]
            inst._scaler = blob["scaler"]
            inst._raw_mean = blob["raw_mean"]
            inst._raw_std = blob["raw_std"]
            inst.backend = "isolation_forest"
            logger.info("VIGIL model loaded from %s", path)
            return inst
        except Exception as exc:  # pragma: no cover
            logger.error("failed to load model from %s: %s", path, exc)
            return None


def load_or_train_default() -> VigilAnomalyModel:
    """
    Return a ready-to-use model: load a persisted one if ``VIGIL_MODEL_PATH`` is
    set and present, else train on a small synthetic benign baseline so the
    detection path is never left without a scorer.
    """
    path = os.getenv(_MODEL_ENV)
    if path and os.path.exists(path):
        loaded = VigilAnomalyModel.load(path)
        if loaded is not None:
            return loaded

    model = VigilAnomalyModel()
    model.train(_synthetic_benign_baseline())
    return model


def _synthetic_benign_baseline(n: int = 2000) -> List[List[float]]:
    """
    Generate a plausible benign baseline (low IoB activity with occasional
    legitimate spikes). Deterministic so training is reproducible.
    """
    try:
        import numpy as np

        rng = np.random.default_rng(7)
        rename = rng.gamma(shape=2.0, scale=0.4, size=n)          # a few renames/sec
        lateral = rng.gamma(shape=1.5, scale=0.3, size=n)
        priv = rng.poisson(lam=0.2, size=n).astype(float)
        vss = np.zeros(n)                                          # benign: no shadow deletion
        return np.stack([rename, lateral, priv, vss], axis=1).tolist()
    except Exception:  # pragma: no cover
        # Pure-python fallback baseline
        import random

        random.seed(7)
        return [
            [random.gammavariate(2.0, 0.4), random.gammavariate(1.5, 0.3), float(random.random() < 0.2), 0.0]
            for _ in range(n)
        ]


def _synthetic_ransomware_positives(n: int = 1000) -> List[List[float]]:
    """
    Generate labelled ransomware-positive IoB vectors (high rename/privesc/VSS
    activity). Used to train the supervised secondary classifier. Deterministic.
    """
    try:
        import numpy as np

        rng = np.random.default_rng(11)
        rename = rng.gamma(shape=6.0, scale=3.0, size=n)          # mass renames
        lateral = rng.gamma(shape=3.0, scale=1.5, size=n)
        priv = rng.poisson(lam=3.5, size=n).astype(float)
        vss = rng.gamma(shape=2.0, scale=1.2, size=n)             # shadow-copy deletion
        return np.stack([rename, lateral, priv, vss], axis=1).tolist()
    except Exception:  # pragma: no cover
        import random

        random.seed(11)
        return [
            [random.gammavariate(6.0, 3.0), random.gammavariate(3.0, 1.5),
             float(random.randint(1, 6)), random.gammavariate(2.0, 1.2)]
            for _ in range(n)
        ]


class SecondaryClassifier:
    """
    Supervised secondary classifier for ensemble validation of anomalies
    (paper Algorithm 1, step 5). Distinguishes true ransomware behaviour from
    benign high-volume operations (e.g. batch file processing) that the
    unsupervised IsolationForest may flag, reducing the false-positive rate.

    Backend preference: TensorFlow/Keras MLP -> scikit-learn MLPClassifier ->
    logistic-regression heuristic. The chosen backend is exposed as
    ``self.backend`` so callers can report which stage-2 model is active.
    """

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold
        self._model = None
        self._scaler = None
        self.backend = "unfitted"

    def train(self, benign: Sequence[Sequence[float]], ransomware: Sequence[Sequence[float]]):
        X = [list(map(float, r)) for r in benign] + [list(map(float, r)) for r in ransomware]
        y = [0] * len(benign) + [1] * len(ransomware)
        try:
            import numpy as np
            from sklearn.preprocessing import StandardScaler

            self._scaler = StandardScaler().fit(np.asarray(X, dtype=float))
            Xs = self._scaler.transform(np.asarray(X, dtype=float))
            ys = np.asarray(y)
            if self._train_tensorflow(Xs, ys):
                self.backend = "tensorflow_mlp"
            else:
                from sklearn.neural_network import MLPClassifier

                self._model = MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=400,
                                            random_state=17).fit(Xs, ys)
                self.backend = "sklearn_mlp"
        except Exception as exc:  # pragma: no cover
            logger.warning("secondary classifier training failed (%s); using logistic heuristic", exc)
            self._fit_logistic(X, y)
        return self

    def _train_tensorflow(self, Xs, ys) -> bool:
        try:
            import tensorflow as tf  # noqa: F401
            from tensorflow import keras

            model = keras.Sequential([
                keras.layers.Input(shape=(len(FEATURES),)),
                keras.layers.Dense(16, activation="relu"),
                keras.layers.Dense(8, activation="relu"),
                keras.layers.Dense(1, activation="sigmoid"),
            ])
            model.compile(optimizer="adam", loss="binary_crossentropy")
            model.fit(Xs, ys, epochs=15, batch_size=32, verbose=0)
            self._model = model
            self._is_keras = True
            return True
        except Exception:
            return False

    def _fit_logistic(self, X, y):
        # Minimal logistic fallback: threshold on rename+vss dominant signal.
        self._model = None
        self.backend = "logistic_heuristic"

    def predict_proba(self, vec: Sequence[float]) -> float:
        v = list(map(float, vec))
        if self.backend == "logistic_heuristic":
            # Higher rename + shadow-copy deletion => ransomware-like.
            score = (v[0] / 20.0) * 0.5 + (v[3] / 4.0) * 0.4 + (v[2] / 6.0) * 0.1
            return max(0.0, min(1.0, score))
        import numpy as np

        Xs = self._scaler.transform(np.asarray([v], dtype=float))
        if getattr(self, "_is_keras", False):
            return float(self._model.predict(Xs, verbose=0)[0][0])
        return float(self._model.predict_proba(Xs)[0][1])

    def is_ransomware(self, vec: Sequence[float]) -> bool:
        return self.predict_proba(vec) >= self.threshold


@dataclass
class EnsembleDetection:
    anomaly_score: float
    secondary_confidence: float
    is_anomaly: bool               # final decision: primary AND secondary agree
    primary_flag: bool
    secondary_flag: bool
    threshold: float
    contributing_features: List[str]
    backend: str                   # "isolation_forest+<secondary>"


class TwoStageDetector:
    """
    VIGIL's two-stage ensemble: IsolationForest anomaly gate (stage 1) followed
    by a supervised classifier that confirms ransomware behaviour (stage 2).
    A CRITICAL alert fires only when both stages agree, which suppresses false
    positives on legitimate high-volume file operations.
    """

    def __init__(self, primary: VigilAnomalyModel, secondary: SecondaryClassifier) -> None:
        self.primary = primary
        self.secondary = secondary
        self.threshold = primary.threshold
        self.contamination = primary.contamination
        self.backend = f"{primary.backend}+{secondary.backend}"

    def score(self, features) -> EnsembleDetection:
        base = self.primary.score(features)
        vec = features.as_list() if isinstance(features, IoBVector) else list(map(float, features))
        secondary_conf = self.secondary.predict_proba(vec)
        secondary_flag = secondary_conf >= self.secondary.threshold
        primary_flag = base.is_anomaly
        return EnsembleDetection(
            anomaly_score=base.anomaly_score,
            secondary_confidence=round(secondary_conf, 4),
            is_anomaly=primary_flag and secondary_flag,
            primary_flag=primary_flag,
            secondary_flag=secondary_flag,
            threshold=base.threshold,
            contributing_features=base.contributing_features,
            backend=self.backend,
        )


def load_or_train_ensemble() -> TwoStageDetector:
    """Return a ready two-stage detector (primary + secondary), training both on
    synthetic baselines if no persisted model is available."""
    primary = load_or_train_default()
    secondary = SecondaryClassifier().train(
        _synthetic_benign_baseline(), _synthetic_ransomware_positives()
    )
    return TwoStageDetector(primary, secondary)
