"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — ML Lifecycle Governance
================================================================
Enterprise ML operations with model versioning, evaluation, and drift detection.

Features:
- Model Version Registry
- Training Dataset Tracking
- Evaluation Metrics (Accuracy, Precision, Recall, F1)
- Confusion Matrix Generation
- Drift Detection
- Model Retraining Pipeline
- A/B Testing Support

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import hashlib
import time
from typing import Dict, Any, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
import logging

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

class ModelStatus(Enum):
    TRAINING = "training"
    VALIDATING = "validating"
    STAGED = "staged"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


@dataclass
class ModelVersion:
    """Model version metadata"""
    model_id: str
    version: str
    name: str
    status: ModelStatus
    created_at: str
    metrics: Dict[str, float]
    parameters: Dict[str, Any]
    dataset_id: Optional[str] = None
    artifact_path: Optional[str] = None
    parent_version: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "model_id": self.model_id,
            "version": self.version,
            "name": self.name,
            "status": self.status.value,
            "created_at": self.created_at,
            "metrics": self.metrics,
            "parameters": self.parameters,
            "dataset_id": self.dataset_id,
            "artifact_path": self.artifact_path,
            "parent_version": self.parent_version,
            "tags": self.tags,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ModelVersion":
        return cls(
            model_id=data["model_id"],
            version=data["version"],
            name=data["name"],
            status=ModelStatus(data["status"]),
            created_at=data["created_at"],
            metrics=data.get("metrics", {}),
            parameters=data.get("parameters", {}),
            dataset_id=data.get("dataset_id"),
            artifact_path=data.get("artifact_path"),
            parent_version=data.get("parent_version"),
            tags=data.get("tags", []),
        )


@dataclass
class Dataset:
    """Training dataset metadata"""
    dataset_id: str
    name: str
    version: str
    created_at: str
    num_samples: int
    features: List[str]
    target: str
    split_ratios: Dict[str, float]  # train, val, test
    source: str
    checksum: str
    
    def to_dict(self) -> Dict:
        return {
            "dataset_id": self.dataset_id,
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "num_samples": self.num_samples,
            "features": self.features,
            "target": self.target,
            "split_ratios": self.split_ratios,
            "source": self.source,
            "checksum": self.checksum,
        }


@dataclass
class EvaluationMetrics:
    """Model evaluation metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: List[List[int]]
    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    custom_metrics: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "confusion_matrix": self.confusion_matrix,
            "roc_auc": self.roc_auc,
            "pr_auc": self.pr_auc,
            "custom_metrics": self.custom_metrics,
        }


@dataclass
class DriftReport:
    """Data/model drift report"""
    timestamp: str
    model_id: str
    version: str
    drift_detected: bool
    drift_score: float
    feature_drifts: Dict[str, float]
    prediction_drift: float
    recommendation: str
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "model_id": self.model_id,
            "version": self.version,
            "drift_detected": self.drift_detected,
            "drift_score": self.drift_score,
            "feature_drifts": self.feature_drifts,
            "prediction_drift": self.prediction_drift,
            "recommendation": self.recommendation,
        }


# ══════════════════════════════════════════════════════════════════════════════
# MODEL REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

class ModelRegistry:
    """
    Central model registry for ML lifecycle management.
    Tracks all model versions, datasets, and evaluations.
    """
    
    def __init__(self, storage_path: str = "data/ml_registry"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.models_path = self.storage_path / "models"
        self.datasets_path = self.storage_path / "datasets"
        self.evaluations_path = self.storage_path / "evaluations"
        self.drift_path = self.storage_path / "drift"
        
        for path in [self.models_path, self.datasets_path, self.evaluations_path, self.drift_path]:
            path.mkdir(exist_ok=True)
        
        self._models: Dict[str, Dict[str, ModelVersion]] = {}
        self._production_models: Dict[str, str] = {}  # model_id -> version
        self._load_registry()
    
    def _load_registry(self):
        """Load registry from storage"""
        index_file = self.storage_path / "registry_index.json"
        if index_file.exists():
            data = json.loads(index_file.read_text())
            self._production_models = data.get("production_models", {})
            
            # Load all model versions
            for model_file in self.models_path.glob("*.json"):
                try:
                    model_data = json.loads(model_file.read_text())
                    mv = ModelVersion.from_dict(model_data)
                    if mv.model_id not in self._models:
                        self._models[mv.model_id] = {}
                    self._models[mv.model_id][mv.version] = mv
                except Exception as e:
                    logger.error(f"Failed to load model {model_file}: {e}")
    
    def _save_registry(self):
        """Save registry index"""
        index_file = self.storage_path / "registry_index.json"
        index_file.write_text(json.dumps({
            "production_models": self._production_models,
            "updated_at": datetime.utcnow().isoformat(),
        }, indent=2))
    
    # ─── MODEL OPERATIONS ─────────────────────────────────────────────────
    
    def register_model(
        self,
        name: str,
        version: str,
        metrics: Dict[str, float],
        parameters: Dict[str, Any],
        dataset_id: Optional[str] = None,
        artifact_path: Optional[str] = None,
        tags: List[str] = None,
    ) -> ModelVersion:
        """Register a new model version"""
        model_id = hashlib.md5(name.encode()).hexdigest()[:12]
        
        # Check for existing version
        if model_id in self._models and version in self._models[model_id]:
            raise ValueError(f"Model {name} version {version} already exists")
        
        # Determine parent version
        parent_version = None
        if model_id in self._models:
            versions = sorted(self._models[model_id].keys())
            if versions:
                parent_version = versions[-1]
        
        model = ModelVersion(
            model_id=model_id,
            version=version,
            name=name,
            status=ModelStatus.STAGED,
            created_at=datetime.utcnow().isoformat(),
            metrics=metrics,
            parameters=parameters,
            dataset_id=dataset_id,
            artifact_path=artifact_path,
            parent_version=parent_version,
            tags=tags or [],
        )
        
        # Store
        if model_id not in self._models:
            self._models[model_id] = {}
        self._models[model_id][version] = model
        
        # Save to file
        model_file = self.models_path / f"{model_id}_{version}.json"
        model_file.write_text(json.dumps(model.to_dict(), indent=2))
        self._save_registry()
        
        logger.info(f"Registered model {name} version {version}")
        return model
    
    def get_model(self, name: str, version: Optional[str] = None) -> Optional[ModelVersion]:
        """Get model by name and version (None for production)"""
        model_id = hashlib.md5(name.encode()).hexdigest()[:12]
        
        if version is None:
            # Get production version
            version = self._production_models.get(model_id)
            if version is None:
                return None
        
        return self._models.get(model_id, {}).get(version)
    
    def list_models(self, name: Optional[str] = None) -> List[ModelVersion]:
        """List all model versions"""
        if name:
            model_id = hashlib.md5(name.encode()).hexdigest()[:12]
            return list(self._models.get(model_id, {}).values())
        
        models = []
        for versions in self._models.values():
            models.extend(versions.values())
        return models
    
    def promote_to_production(self, name: str, version: str) -> ModelVersion:
        """Promote model version to production"""
        model = self.get_model(name, version)
        if model is None:
            raise ValueError(f"Model {name} version {version} not found")
        
        # Demote current production
        current_prod = self._production_models.get(model.model_id)
        if current_prod and current_prod in self._models.get(model.model_id, {}):
            self._models[model.model_id][current_prod].status = ModelStatus.DEPRECATED
        
        # Promote new version
        model.status = ModelStatus.PRODUCTION
        self._production_models[model.model_id] = version
        
        # Save
        model_file = self.models_path / f"{model.model_id}_{version}.json"
        model_file.write_text(json.dumps(model.to_dict(), indent=2))
        self._save_registry()
        
        logger.info(f"Promoted {name} version {version} to production")
        return model
    
    # ─── DATASET OPERATIONS ───────────────────────────────────────────────
    
    def register_dataset(
        self,
        name: str,
        version: str,
        num_samples: int,
        features: List[str],
        target: str,
        split_ratios: Dict[str, float],
        source: str,
        data_checksum: str,
    ) -> Dataset:
        """Register training dataset"""
        dataset_id = hashlib.md5(f"{name}:{version}".encode()).hexdigest()[:12]
        
        dataset = Dataset(
            dataset_id=dataset_id,
            name=name,
            version=version,
            created_at=datetime.utcnow().isoformat(),
            num_samples=num_samples,
            features=features,
            target=target,
            split_ratios=split_ratios,
            source=source,
            checksum=data_checksum,
        )
        
        # Save
        dataset_file = self.datasets_path / f"{dataset_id}.json"
        dataset_file.write_text(json.dumps(dataset.to_dict(), indent=2))
        
        logger.info(f"Registered dataset {name} version {version}")
        return dataset
    
    def get_dataset(self, dataset_id: str) -> Optional[Dataset]:
        """Get dataset by ID"""
        dataset_file = self.datasets_path / f"{dataset_id}.json"
        if dataset_file.exists():
            data = json.loads(dataset_file.read_text())
            return Dataset(**data)
        return None
    
    # ─── EVALUATION OPERATIONS ────────────────────────────────────────────
    
    def save_evaluation(
        self,
        model_name: str,
        version: str,
        metrics: EvaluationMetrics,
    ) -> str:
        """Save model evaluation results"""
        model = self.get_model(model_name, version)
        if model is None:
            raise ValueError(f"Model {model_name} version {version} not found")
        
        eval_id = f"{model.model_id}_{version}_{int(time.time())}"
        eval_file = self.evaluations_path / f"{eval_id}.json"
        
        eval_data = {
            "eval_id": eval_id,
            "model_id": model.model_id,
            "model_name": model_name,
            "version": version,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": metrics.to_dict(),
        }
        
        eval_file.write_text(json.dumps(eval_data, indent=2))
        
        # Update model metrics
        model.metrics.update({
            "accuracy": metrics.accuracy,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1_score": metrics.f1_score,
        })
        
        model_file = self.models_path / f"{model.model_id}_{version}.json"
        model_file.write_text(json.dumps(model.to_dict(), indent=2))
        
        logger.info(f"Saved evaluation for {model_name} version {version}")
        return eval_id
    
    def get_evaluations(self, model_name: str, version: Optional[str] = None) -> List[Dict]:
        """Get evaluation history for model"""
        model_id = hashlib.md5(model_name.encode()).hexdigest()[:12]
        evaluations = []
        
        for eval_file in self.evaluations_path.glob(f"{model_id}_*.json"):
            data = json.loads(eval_file.read_text())
            if version is None or data.get("version") == version:
                evaluations.append(data)
        
        return sorted(evaluations, key=lambda x: x["timestamp"], reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# DRIFT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

class DriftDetector:
    """
    Detect data and model drift.
    Uses statistical tests to identify distribution changes.
    """
    
    def __init__(self, threshold: float = 0.1):
        self.threshold = threshold
        self._baseline_stats: Dict[str, Dict] = {}
    
    def set_baseline(self, feature_name: str, values: List[float]):
        """Set baseline statistics for a feature"""
        import statistics
        
        self._baseline_stats[feature_name] = {
            "mean": statistics.mean(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0,
            "min": min(values),
            "max": max(values),
            "count": len(values),
        }
    
    def detect_drift(
        self,
        model_name: str,
        version: str,
        current_features: Dict[str, List[float]],
        current_predictions: List[float],
        baseline_predictions: List[float],
    ) -> DriftReport:
        """Detect drift in features and predictions"""
        import statistics
        
        feature_drifts = {}
        max_drift = 0.0
        
        # Check feature drift
        for feature, values in current_features.items():
            if feature in self._baseline_stats:
                baseline = self._baseline_stats[feature]
                current_mean = statistics.mean(values)
                current_stdev = statistics.stdev(values) if len(values) > 1 else 0
                
                # Calculate normalized drift
                if baseline["stdev"] > 0:
                    drift = abs(current_mean - baseline["mean"]) / baseline["stdev"]
                else:
                    drift = abs(current_mean - baseline["mean"]) / (baseline["mean"] + 1e-10)
                
                feature_drifts[feature] = drift
                max_drift = max(max_drift, drift)
        
        # Check prediction drift
        baseline_mean = statistics.mean(baseline_predictions)
        current_mean = statistics.mean(current_predictions)
        baseline_stdev = statistics.stdev(baseline_predictions) if len(baseline_predictions) > 1 else 1
        
        prediction_drift = abs(current_mean - baseline_mean) / (baseline_stdev + 1e-10)
        
        # Calculate overall drift score
        drift_score = max(max_drift, prediction_drift)
        drift_detected = drift_score > self.threshold
        
        # Generate recommendation
        if drift_detected:
            if prediction_drift > max_drift:
                recommendation = "RETRAIN: Significant prediction drift detected. Model may need retraining."
            else:
                top_features = sorted(feature_drifts.items(), key=lambda x: x[1], reverse=True)[:3]
                recommendation = f"INVESTIGATE: Feature drift in {', '.join(f[0] for f in top_features)}. Consider retraining."
        else:
            recommendation = "STABLE: No significant drift detected."
        
        return DriftReport(
            timestamp=datetime.utcnow().isoformat(),
            model_id=hashlib.md5(model_name.encode()).hexdigest()[:12],
            version=version,
            drift_detected=drift_detected,
            drift_score=drift_score,
            feature_drifts=feature_drifts,
            prediction_drift=prediction_drift,
            recommendation=recommendation,
        )


# ══════════════════════════════════════════════════════════════════════════════
# EVALUATION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def calculate_metrics(
    y_true: List[int],
    y_pred: List[int],
    num_classes: int = 2,
) -> EvaluationMetrics:
    """Calculate evaluation metrics from predictions"""
    # Build confusion matrix
    confusion = [[0] * num_classes for _ in range(num_classes)]
    for true, pred in zip(y_true, y_pred):
        confusion[true][pred] += 1
    
    # Calculate metrics
    tp = confusion[1][1] if num_classes == 2 else sum(confusion[i][i] for i in range(num_classes))
    fp = confusion[0][1] if num_classes == 2 else sum(confusion[i][j] for i in range(num_classes) for j in range(num_classes) if i != j)
    fn = confusion[1][0] if num_classes == 2 else sum(confusion[i][j] for i in range(num_classes) for j in range(num_classes) if i != j)
    tn = confusion[0][0] if num_classes == 2 else 0
    
    total = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    
    accuracy = correct / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return EvaluationMetrics(
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1,
        confusion_matrix=confusion,
    )


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

_registry_instance: Optional[ModelRegistry] = None
_detector_instance: Optional[DriftDetector] = None


def get_registry() -> ModelRegistry:
    """Get model registry singleton"""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = ModelRegistry()
    return _registry_instance


def get_drift_detector(threshold: float = 0.1) -> DriftDetector:
    """Get drift detector singleton"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = DriftDetector(threshold)
    return _detector_instance


__all__ = [
    "ModelStatus",
    "ModelVersion",
    "Dataset",
    "EvaluationMetrics",
    "DriftReport",
    "ModelRegistry",
    "DriftDetector",
    "calculate_metrics",
    "get_registry",
    "get_drift_detector",
]
