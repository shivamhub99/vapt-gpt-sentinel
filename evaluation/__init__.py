"""
evaluation package initialization.
Exports evaluation metrics, comparative baselines, and academic benchmark runner.
"""

from evaluation.baselines import (
    BaselineComparator,
    StrategyResult,
    baseline_comparator,
)
from evaluation.benchmark import BenchmarkRunner, benchmark_runner
from evaluation.metrics import (
    EvaluationMetrics,
    MetricsCalculator,
    metrics_calculator,
)

__all__ = [
    "BaselineComparator",
    "BenchmarkRunner",
    "EvaluationMetrics",
    "MetricsCalculator",
    "StrategyResult",
    "baseline_comparator",
    "benchmark_runner",
    "metrics_calculator",
]
