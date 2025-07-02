"""
Machine learning engine for AI-generated package pattern detection.

Implements advanced pattern recognition using trained models to identify
AI-generated dependency names and suspicious package characteristics.
"""

import math
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from .cli_config import get_config
from .error_handling import ErrorCategory, get_error_handler
from .registry_clients import PackageInfo

# Security constants for ML model protection
ALLOWED_CONFIDENCE_RANGE = (0.0, 1.0)  # Valid confidence range
ALLOWED_PROBABILITY_RANGE = (0.0, 1.0)  # Valid probability range


# Thread-safe singleton lock
_ml_engine_lock = threading.RLock()
_ml_engine_instance: Optional["MLPatternEngine"] = None
_ml_engine_created_at: Optional[float] = None
_ml_engine_access_count: int = 0

# Cache cleanup configuration
_ML_CACHE_TTL_SECONDS = 3600  # 1 hour TTL for ML engine cache
_ML_CACHE_MAX_ACCESS_COUNT = 10000  # Reset after 10K accesses to prevent memory leaks


def _get_ml_config_constants():
    """Get ML configuration constants with fallback to defaults."""
    try:
        config = get_config()
        return {
            "MAX_INPUT_LENGTH": config.security.max_input_length,
            "MAX_FEATURE_VALUE": config.ml.max_feature_value,
            "MIN_FEATURE_VALUE": config.ml.min_feature_value,
            "MAX_DESCRIPTION_LENGTH": config.security.max_description_length,
            "MAX_AUTHOR_LENGTH": config.security.max_author_length,
        }
    except Exception:
        # Fallback to defaults if config loading fails
        return {
            "MAX_INPUT_LENGTH": 1000,
            "MAX_FEATURE_VALUE": 10.0,
            "MIN_FEATURE_VALUE": -10.0,
            "MAX_DESCRIPTION_LENGTH": 5000,
            "MAX_AUTHOR_LENGTH": 200,
        }


# Get constants from config
_CONFIG_CONSTANTS = _get_ml_config_constants()
MAX_INPUT_LENGTH = _CONFIG_CONSTANTS["MAX_INPUT_LENGTH"]
MAX_FEATURE_VALUE = _CONFIG_CONSTANTS["MAX_FEATURE_VALUE"]
MIN_FEATURE_VALUE = _CONFIG_CONSTANTS["MIN_FEATURE_VALUE"]
MAX_DESCRIPTION_LENGTH = _CONFIG_CONSTANTS["MAX_DESCRIPTION_LENGTH"]
MAX_AUTHOR_LENGTH = _CONFIG_CONSTANTS["MAX_AUTHOR_LENGTH"]


def _validate_string_input(
    value: Any, field_name: str, max_length: Optional[int] = None
) -> str:
    """
    Validate and sanitize string inputs for ML processing.

    Args:
        value: Input value to validate
        field_name: Name of the field for error reporting
        max_length: Maximum allowed length (defaults to config value)

    Returns:
        str: Validated and sanitized string

    Raises:
        ValueError: If input is invalid
    """
    if value is None:
        return ""

    if not isinstance(value, (str, int, float)):
        raise ValueError(
            f"Invalid {field_name}: must be string-like, got {type(value)}"
        )

    # Convert to string safely
    try:
        str_value = str(value).strip()
    except (UnicodeError, ValueError) as e:
        raise ValueError(f"Cannot convert {field_name} to string: {e}")

    # Get max length from config if not provided
    if max_length is None:
        config = get_config()
        max_length = config.security.max_input_length

    # Length validation
    if len(str_value) > max_length:
        raise ValueError(
            f"{field_name} too long: {len(str_value)} chars (max: {max_length})"
        )

    # Basic sanitization - remove null bytes and control characters
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", str_value)

    return sanitized


def _clamp_feature_value(value: float, feature_name: str = "feature") -> float:
    """
    Clamp feature values to safe ranges to prevent adversarial inputs.

    Args:
        value: Feature value to clamp
        feature_name: Name of feature for logging

    Returns:
        float: Clamped value within safe range
    """
    if not isinstance(value, (int, float)) or math.isnan(value) or math.isinf(value):
        # Log suspicious input but don't expose details
        get_error_handler().warning(
            ErrorCategory.ML_MODEL,
            "Invalid feature value detected, using default",
            "ml_engine",
            "_clamp_feature_value",
            details={"feature_name": feature_name},
        )
        return 0.0

    # Get feature value limits from config
    config = get_config()
    min_value = config.ml.min_feature_value
    max_value = config.ml.max_feature_value

    return max(min_value, min(max_value, float(value)))


def _validate_probability(value: float, field_name: str = "probability") -> float:
    """
    Validate and clamp probability values.

    Args:
        value: Probability value to validate
        field_name: Field name for error reporting

    Returns:
        float: Valid probability between 0.0 and 1.0
    """
    if not isinstance(value, (int, float)) or math.isnan(value) or math.isinf(value):
        get_error_handler().warning(
            ErrorCategory.ML_MODEL,
            "Invalid probability value detected, using default",
            "ml_engine",
            "_validate_probability",
            details={"field_name": field_name},
        )
        return 0.0

    return max(0.0, min(1.0, float(value)))


def _robust_feature_extraction(
    package_name: str, max_iterations: int = 100
) -> Dict[str, float]:
    """
    Perform robust feature extraction with protection against adversarial inputs.

    Args:
        package_name: Package name to extract features from
        max_iterations: Maximum iterations to prevent infinite loops

    Returns:
        Dict[str, float]: Extracted features with clamped values
    """
    try:
        # Validate input
        safe_name = _validate_string_input(
            package_name, "package_name", MAX_INPUT_LENGTH
        )

        if not safe_name:
            return {"empty_name": 1.0}

        features = {}
        iteration_count = 0

        # Safe feature extraction with iteration limits
        name_lower = safe_name.lower()

        # Length-based features with bounds checking
        name_len = len(safe_name)
        features["name_length_normalized"] = _clamp_feature_value(
            min(name_len / 50.0, 1.0)
        )
        features["excessive_length"] = _clamp_feature_value(
            1.0 if name_len > 25 else 0.0
        )

        # Separator features with protection against excessive iterations
        separator_count = 0
        for char in name_lower[:max_iterations]:  # Limit character iterations
            iteration_count += 1
            if char in ["-", "_"]:
                separator_count += 1
            if iteration_count >= max_iterations:
                break

        features["separator_density"] = _clamp_feature_value(
            min(separator_count / max(name_len, 1), 1.0)
        )
        features["excessive_separators"] = _clamp_feature_value(
            1.0 if separator_count >= 3 else 0.0
        )

        # Pattern matching with safe regex
        try:
            # AI keyword features
            ai_keywords = ["ai", "ml", "smart", "auto", "intelligent", "advanced"]
            features["ai_keyword_presence"] = _clamp_feature_value(
                float(any(kw in name_lower for kw in ai_keywords))
            )

            # Utility patterns
            utility_patterns = ["utils", "helper", "tools", "lib", "core", "pro"]
            features["utility_pattern"] = _clamp_feature_value(
                float(any(pattern in name_lower for pattern in utility_patterns))
            )

            # Action verb patterns
            action_verbs = ["generate", "process", "analyze", "validate", "optimize"]
            features["action_verb_pattern"] = _clamp_feature_value(
                float(any(verb in name_lower for verb in action_verbs))
            )

            # Compound word analysis with safe regex
            word_matches = re.findall(r"[a-z]+", name_lower)
            word_count = len(word_matches[:20])  # Limit to prevent DoS
            features["compound_complexity"] = _clamp_feature_value(
                min(word_count / 5.0, 1.0)
            )
            features["excessive_compounds"] = _clamp_feature_value(
                1.0 if word_count >= 4 else 0.0
            )

            # Version number in name (safe regex)
            version_match = re.search(r"\d+(\.\d+)*$", safe_name)
            features["version_in_name"] = _clamp_feature_value(
                float(bool(version_match))
            )

            # Character repetition (safe regex with limits)
            repetition_match = re.search(
                r"(.)\1{2,}", name_lower[:100]
            )  # Limit search length
            features["character_repetition"] = _clamp_feature_value(
                float(bool(repetition_match))
            )

        except re.error as e:
            # If regex fails, use safe defaults
            get_error_handler().warning(
                ErrorCategory.ML_MODEL,
                "Regex error in feature extraction, using safe defaults",
                "ml_engine",
                "_robust_feature_extraction",
                exception=e,
            )
            features["ai_keyword_presence"] = 0.0
            features["utility_pattern"] = 0.0
            features["action_verb_pattern"] = 0.0
            features["compound_complexity"] = 0.0
            features["excessive_compounds"] = 0.0
            features["version_in_name"] = 0.0
            features["character_repetition"] = 0.0

        return features

    except Exception as e:
        # Don't expose internal errors
        get_error_handler().warning(
            ErrorCategory.ML_MODEL,
            "Feature extraction error, using safe defaults",
            "ml_engine",
            "_robust_feature_extraction",
            exception=e,
        )
        return {"extraction_error": 1.0}


class MLModelType(Enum):
    """Types of ML models for pattern detection."""

    NAMING_CLASSIFIER = "naming_classifier"
    SEMANTIC_ANALYZER = "semantic_analyzer"
    BEHAVIORAL_DETECTOR = "behavioral_detector"
    ENSEMBLE_PREDICTOR = "ensemble_predictor"


@dataclass(frozen=True)
class MLPrediction:
    """Result of a machine learning prediction."""

    model_type: MLModelType
    confidence: float  # 0.0 = not AI-generated, 1.0 = definitely AI-generated
    probability: float  # Raw model probability
    features_detected: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate prediction values after initialization."""
        # Validate confidence and probability ranges
        object.__setattr__(
            self, "confidence", _validate_probability(self.confidence, "confidence")
        )
        object.__setattr__(
            self, "probability", _validate_probability(self.probability, "probability")
        )

        # Validate features_detected
        if not isinstance(self.features_detected, list):
            object.__setattr__(self, "features_detected", [])

        # Limit feature list size to prevent memory exhaustion
        if len(self.features_detected) > 100:
            object.__setattr__(self, "features_detected", self.features_detected[:100])


@dataclass(frozen=True)
class PatternAnalysisResult:
    """Complete ML analysis result for a package."""

    package_name: str
    overall_ai_probability: float  # Ensemble prediction
    model_predictions: List[MLPrediction] = field(default_factory=list)
    detected_patterns: List[str] = field(default_factory=list)
    confidence_level: str = "MEDIUM"  # HIGH, MEDIUM, LOW

    def __post_init__(self):
        """Validate analysis result after initialization."""
        # Validate package name
        safe_name = _validate_string_input(
            self.package_name, "package_name", MAX_INPUT_LENGTH
        )
        object.__setattr__(self, "package_name", safe_name)

        # Validate probability
        safe_prob = _validate_probability(
            self.overall_ai_probability, "overall_ai_probability"
        )
        object.__setattr__(self, "overall_ai_probability", safe_prob)

        # Validate confidence level
        valid_levels = {"HIGH", "MEDIUM", "LOW"}
        if self.confidence_level not in valid_levels:
            object.__setattr__(self, "confidence_level", "MEDIUM")

        # Limit pattern list size
        if len(self.detected_patterns) > 50:
            object.__setattr__(self, "detected_patterns", self.detected_patterns[:50])

    @property
    def is_likely_ai_generated(self) -> bool:
        """Check if the package is likely AI-generated."""
        return self.overall_ai_probability >= 0.7

    @property
    def is_highly_likely_ai_generated(self) -> bool:
        """Check if the package is highly likely AI-generated."""
        return self.overall_ai_probability >= 0.85


class NamingPatternClassifier:
    """
    ML-based classifier for detecting AI-generated naming patterns.

    Uses feature extraction and statistical models to identify characteristic
    patterns in AI-generated package names.
    """

    def __init__(self):
        """Initialize the naming pattern classifier."""
        self.feature_weights = self._initialize_feature_weights()
        self.vocabulary = self._build_vocabulary()

    def predict(
        self, package_name: str, registry_type: str = "unknown"
    ) -> MLPrediction:
        """
        Predict if a package name was likely generated by AI.

        Args:
            package_name: The package name to analyze
            registry_type: Type of registry (pypi, npm)

        Returns:
            MLPrediction with confidence and features
        """
        try:
            # Validate inputs first
            safe_name = _validate_string_input(
                package_name, "package_name", MAX_INPUT_LENGTH
            )
            safe_registry = _validate_string_input(registry_type, "registry_type", 50)

            if not safe_name:
                return MLPrediction(
                    model_type=MLModelType.NAMING_CLASSIFIER,
                    confidence=0.0,
                    probability=0.0,
                    features_detected=["empty_name"],
                    evidence={"error": "empty_package_name"},
                )

            features = self._extract_features(safe_name, safe_registry)

            # Calculate weighted score with bounds checking
            weighted_score = 0.0
            total_weight = 0.0
            features_detected = []

            for feature_name, feature_value in features.items():
                # Clamp feature values and weights
                safe_feature_value = _clamp_feature_value(feature_value, feature_name)
                weight = self.feature_weights.get(feature_name, 0.1)
                weight = _clamp_feature_value(weight, f"{feature_name}_weight")

                weighted_score += safe_feature_value * weight
                total_weight += abs(weight)  # Use absolute weight for normalization

                if safe_feature_value > 0.5:  # Feature is present
                    features_detected.append(feature_name)

            # Normalize score with protection against division by zero
            if total_weight > 0:
                probability = _validate_probability(weighted_score / total_weight)
            else:
                probability = 0.0

            # Apply sigmoid-like confidence adjustment
            confidence = self._calculate_confidence(probability, len(features_detected))

            return MLPrediction(
                model_type=MLModelType.NAMING_CLASSIFIER,
                confidence=confidence,
                probability=probability,
                features_detected=features_detected[:50],  # Limit feature list
                evidence={
                    "features": features,
                    "total_features": len(features_detected),
                },
            )

        except Exception:
            # Return safe default on any error
            print("Warning: Error in naming classifier prediction, using safe default")
            return MLPrediction(
                model_type=MLModelType.NAMING_CLASSIFIER,
                confidence=0.0,
                probability=0.0,
                features_detected=["prediction_error"],
                evidence={"error": "classification_failed"},
            )

    def _extract_features(
        self, package_name: str, registry_type: str
    ) -> Dict[str, float]:
        """Extract numerical features from package name with security validation."""
        try:
            # Use robust feature extraction as base
            features = _robust_feature_extraction(package_name)

            # Add registry-specific features with validation
            safe_registry = _validate_string_input(registry_type, "registry_type", 50)
            safe_name = _validate_string_input(
                package_name, "package_name", MAX_INPUT_LENGTH
            )

            if safe_registry == "npm" and safe_name:
                features["scoped_package"] = _clamp_feature_value(
                    float(safe_name.startswith("@"))
                )
            else:
                features["scoped_package"] = 0.0

            # Vocabulary coherence with safe word extraction
            name_lower = safe_name.lower() if safe_name else ""
            features["vocabulary_coherence"] = self._calculate_vocabulary_coherence(
                name_lower
            )

            # Ensure all feature values are clamped
            for feature_name in features:
                features[feature_name] = _clamp_feature_value(
                    features[feature_name], feature_name
                )

            return features

        except Exception:
            print("Warning: Feature extraction failed, using safe defaults")
            return {"extraction_error": 1.0}

    def _calculate_vocabulary_coherence(self, name_lower: str) -> float:
        """Calculate how coherent the vocabulary usage is."""
        words = re.findall(r"[a-z]+", name_lower)
        if len(words) < 2:
            return 1.0  # Single words are coherent

        # Check if words commonly appear together in real packages
        coherence_score = 0.0
        for i, word in enumerate(words):
            if word in self.vocabulary:
                coherence_score += 1.0

        return coherence_score / len(words) if words else 0.0

    def _calculate_confidence(self, probability: float, feature_count: int) -> float:
        """Calculate confidence based on probability and feature support."""
        # More features detected = higher confidence
        feature_confidence = min(feature_count / 5.0, 1.0)

        # Sigmoid-like transformation for probability
        prob_confidence = 2 * probability * (1 - probability)  # Peak at 0.5

        return min((probability + feature_confidence + prob_confidence) / 3.0, 1.0)

    def _initialize_feature_weights(self) -> Dict[str, float]:
        """Initialize feature weights based on importance."""
        return {
            "ai_keyword_presence": 0.25,
            "utility_pattern": 0.20,
            "action_verb_pattern": 0.15,
            "excessive_separators": 0.15,
            "compound_complexity": 0.10,
            "version_in_name": 0.08,
            "excessive_length": 0.07,
            "vocabulary_coherence": -0.20,  # Negative weight (coherent = less suspicious)
            "character_repetition": 0.05,
            "separator_density": 0.05,
            "excessive_compounds": 0.05,
            "scoped_package": -0.05,  # Scoped packages often more legitimate
        }

    def _build_vocabulary(self) -> Set[str]:
        """Build vocabulary of common legitimate package name components."""
        return {
            # Common technical terms
            "api",
            "web",
            "http",
            "json",
            "xml",
            "sql",
            "db",
            "auth",
            "oauth",
            "client",
            "server",
            "parser",
            "config",
            "test",
            "dev",
            "prod",
            # Common actions
            "parse",
            "fetch",
            "send",
            "get",
            "post",
            "read",
            "write",
            "load",
            # Common objects
            "data",
            "file",
            "image",
            "text",
            "email",
            "time",
            "date",
            "user",
            # Legitimate utility words
            "utils",
            "helpers",
            "tools",
            "lib",
            "core",
            "base",
            "common",
        }


class SemanticAnalyzer:
    """
    Semantic analysis engine for package descriptions and metadata.

    Analyzes textual content to detect AI-generated descriptions and
    characteristics typical of AI-created packages.
    """

    def __init__(self):
        """Initialize the semantic analyzer."""
        self.feature_weights = self._initialize_feature_weights()
        self.vocabulary = self._build_vocabulary()

    def analyze_package_metadata(self, package_info: PackageInfo) -> MLPrediction:
        """
        Analyze package metadata for AI-generated characteristics.

        Args:
            package_info: Package information to analyze

        Returns:
            MLPrediction with semantic analysis results
        """
        try:
            # Validate input
            if not package_info:
                return MLPrediction(
                    model_type=MLModelType.SEMANTIC_ANALYZER,
                    confidence=0.0,
                    probability=0.0,
                    features_detected=["no_package_info"],
                    evidence={"error": "missing_package_info"},
                )

            features_detected = []
            evidence = {}

            # Analyze description with input validation
            description = _validate_string_input(
                package_info.description or "", "description", MAX_DESCRIPTION_LENGTH
            )
            description_score = self._analyze_description(description)
            description_score = _clamp_feature_value(
                description_score, "description_score"
            )

            if description_score > 0.5:
                features_detected.append("suspicious_description")
            evidence["description_score"] = description_score

            # Analyze author patterns with input validation
            author = _validate_string_input(
                package_info.author or "", "author", MAX_AUTHOR_LENGTH
            )
            author_score = self._analyze_author(author)
            author_score = _clamp_feature_value(author_score, "author_score")

            if author_score > 0.5:
                features_detected.append("suspicious_author")
            evidence["author_score"] = author_score

            # Analyze metadata completeness patterns
            completeness_score = self._analyze_completeness_pattern(package_info)
            completeness_score = _clamp_feature_value(
                completeness_score, "completeness_score"
            )

            if completeness_score > 0.5:
                features_detected.append("suspicious_metadata_pattern")
            evidence["completeness_score"] = completeness_score

            # Calculate overall semantic probability with bounds checking
            scores = [description_score, author_score, completeness_score]
            valid_scores = [
                s for s in scores if isinstance(s, (int, float)) and not math.isnan(s)
            ]

            if valid_scores:
                probability = _validate_probability(
                    sum(valid_scores) / len(valid_scores)
                )
            else:
                probability = 0.0

            confidence = self._calculate_semantic_confidence(
                probability, len(features_detected)
            )

            return MLPrediction(
                model_type=MLModelType.SEMANTIC_ANALYZER,
                confidence=confidence,
                probability=probability,
                features_detected=features_detected[:50],  # Limit feature list
                evidence=evidence,
            )

        except Exception:
            # Return safe default on any error
            print("Warning: Error in semantic analysis, using safe default")
            return MLPrediction(
                model_type=MLModelType.SEMANTIC_ANALYZER,
                confidence=0.0,
                probability=0.0,
                features_detected=["analysis_error"],
                evidence={"error": "semantic_analysis_failed"},
            )

    def _analyze_description(self, description: str) -> float:
        """Analyze package description for AI-generated characteristics."""
        if not description or len(description.strip()) < 10:
            return 0.3  # Very short/empty descriptions are moderately suspicious

        desc_lower = description.lower()
        score = 0.0

        # AI-typical phrases
        ai_phrases = [
            "powerful tool",
            "easy to use",
            "simple and",
            "lightweight",
            "designed to",
            "allows you to",
            "provides a",
            "makes it easy",
            "comprehensive solution",
            "cutting-edge",
            "state-of-the-art",
        ]

        phrase_matches = sum(1 for phrase in ai_phrases if phrase in desc_lower)
        score += min(phrase_matches * 0.2, 0.6)

        # Generic/vague descriptions
        if any(word in desc_lower for word in ["utility", "helper", "tool", "library"]):
            if len(description.split()) < 15:  # Short + generic = suspicious
                score += 0.3

        # Repetitive language patterns
        words = desc_lower.split()
        if len(words) > 10:
            unique_words = len(set(words))
            repetition_ratio = unique_words / len(words)
            if repetition_ratio < 0.7:  # High repetition
                score += 0.2

        # Placeholder-like content
        placeholder_indicators = ["todo", "placeholder", "example", "test", "lorem"]
        if any(indicator in desc_lower for indicator in placeholder_indicators):
            score += 0.4

        return min(score, 1.0)

    def _analyze_author(self, author: str) -> float:
        """Analyze author information for suspicious patterns."""
        if not author or len(author.strip()) < 3:
            return 0.4  # Missing author is somewhat suspicious

        author_lower = author.lower()
        score = 0.0

        # Generic/placeholder author names
        generic_authors = [
            "admin",
            "user",
            "test",
            "developer",
            "author",
            "owner",
            "maintainer",
            "bot",
            "ai",
            "automated",
            "generator",
        ]

        if any(generic in author_lower for generic in generic_authors):
            score += 0.5

        # Very short names (often AI-generated)
        if len(author.strip()) <= 5:
            score += 0.3

        # Numbers in author name (less common for real developers)
        if re.search(r"\d", author):
            score += 0.2

        return min(score, 1.0)

    def _analyze_completeness_pattern(self, package_info: PackageInfo) -> float:
        """Analyze metadata completeness patterns typical of AI generation."""
        score = 0.0

        # Check for minimal metadata (AI often creates packages with just basics)
        missing_count = 0
        if not package_info.homepage:
            missing_count += 1
        if not package_info.repository:
            missing_count += 1
        if not package_info.license:
            missing_count += 1

        # Some missing metadata is normal, but all missing is suspicious
        if missing_count >= 3:
            score += 0.4
        elif missing_count >= 2:
            score += 0.2

        # Very recent packages with minimal metadata
        if package_info.created_at:
            # This is a simplified check - in production you'd parse the date
            if "2024" in package_info.created_at or "2023" in package_info.created_at:
                if missing_count >= 2:
                    score += 0.3

        return min(score, 1.0)

    def _calculate_semantic_confidence(
        self, probability: float, feature_count: int
    ) -> float:
        """Calculate confidence for semantic analysis."""
        base_confidence = probability
        feature_confidence = min(feature_count / 3.0, 1.0)

        return min((base_confidence + feature_confidence) / 2.0, 1.0)

    def _initialize_feature_weights(self) -> Dict[str, float]:
        """Initialize feature weights based on importance."""
        return {
            "ai_keyword_presence": 0.25,
            "utility_pattern": 0.20,
            "action_verb_pattern": 0.15,
            "excessive_separators": 0.15,
            "compound_complexity": 0.10,
            "version_in_name": 0.08,
            "excessive_length": 0.07,
            "vocabulary_coherence": -0.20,  # Negative weight
        }

    def _build_vocabulary(self) -> Set[str]:
        """Build vocabulary of common legitimate package name components."""
        return {
            "api",
            "web",
            "http",
            "json",
            "xml",
            "sql",
            "auth",
            "client",
            "server",
            "parser",
            "config",
            "test",
            "data",
            "file",
            "image",
            "text",
            "email",
            "time",
            "date",
            "user",
            "parse",
            "fetch",
            "send",
            "get",
            "post",
            "read",
            "write",
            "load",
            "utils",
            "helpers",
            "tools",
            "lib",
            "core",
            "base",
            "common",
        }


class BehavioralDetector:
    """
    Behavioral pattern detector for package release and maintenance patterns.

    Analyzes temporal patterns and maintenance behaviors that might indicate
    AI-generated or quickly uploaded packages.
    """

    def analyze_behavioral_patterns(self, package_info: PackageInfo) -> MLPrediction:
        """
        Analyze behavioral patterns in package lifecycle.

        Args:
            package_info: Package information to analyze

        Returns:
            MLPrediction with behavioral analysis
        """
        features_detected = []
        evidence = {}

        # Analyze version patterns
        version_score = self._analyze_version_pattern(package_info)
        if version_score > 0.5:
            features_detected.append("suspicious_version_pattern")
        evidence["version_score"] = version_score

        probability = version_score
        confidence = min(probability + (len(features_detected) * 0.2), 1.0)

        return MLPrediction(
            model_type=MLModelType.BEHAVIORAL_DETECTOR,
            confidence=confidence,
            probability=probability,
            features_detected=features_detected,
            evidence=evidence,
        )

    def _analyze_version_pattern(self, package_info: PackageInfo) -> float:
        """Analyze version numbering patterns."""
        if not package_info.version:
            return 0.2

        version = package_info.version.strip()
        score = 0.0

        # Initial versions are more suspicious for new packages
        if version in ["1.0.0", "0.1.0", "0.0.1"]:
            score += 0.4

        # Pre-release patterns
        if re.match(r"^0\.0\.\d+$", version):
            score += 0.3

        return min(score, 1.0)


class MLPatternEngine:
    """
    Main ML engine that coordinates multiple models for comprehensive analysis.

    Implements ensemble methods combining multiple ML approaches for
    robust AI-generated package detection.
    """

    def __init__(self):
        """Initialize the ML pattern engine."""
        self.naming_classifier = NamingPatternClassifier()
        self.semantic_analyzer = SemanticAnalyzer()
        self.behavioral_detector = BehavioralDetector()

        # Ensemble weights for combining predictions
        self.model_weights = {
            MLModelType.NAMING_CLASSIFIER: 0.4,
            MLModelType.SEMANTIC_ANALYZER: 0.35,
            MLModelType.BEHAVIORAL_DETECTOR: 0.25,
        }

    async def analyze_package(
        self, package_info: PackageInfo, registry_type: str = "unknown"
    ) -> PatternAnalysisResult:
        """
        Perform comprehensive ML analysis of a package.

        Args:
            package_info: Package information to analyze
            registry_type: Type of registry (pypi, npm)

        Returns:
            PatternAnalysisResult with ensemble predictions
        """
        if not package_info or not package_info.exists:
            # Package doesn't exist - return neutral ML analysis
            return PatternAnalysisResult(
                package_name=package_info.name if package_info else "unknown",
                overall_ai_probability=0.0,
                confidence_level="LOW",
            )

        # Run all ML models
        model_predictions = []

        # Naming pattern analysis
        naming_prediction = self.naming_classifier.predict(
            package_info.name, registry_type
        )
        model_predictions.append(naming_prediction)

        # Semantic analysis
        semantic_prediction = self.semantic_analyzer.analyze_package_metadata(
            package_info
        )
        model_predictions.append(semantic_prediction)

        # Behavioral analysis
        behavioral_prediction = self.behavioral_detector.analyze_behavioral_patterns(
            package_info
        )
        model_predictions.append(behavioral_prediction)

        # Ensemble prediction
        overall_probability = self._calculate_ensemble_prediction(model_predictions)

        # Collect all detected patterns
        all_patterns = []
        for prediction in model_predictions:
            all_patterns.extend(prediction.features_detected)

        # Determine confidence level
        confidence_level = self._determine_confidence_level(
            overall_probability, model_predictions
        )

        return PatternAnalysisResult(
            package_name=package_info.name,
            overall_ai_probability=overall_probability,
            model_predictions=model_predictions,
            detected_patterns=all_patterns,
            confidence_level=confidence_level,
        )

    def _calculate_ensemble_prediction(self, predictions: List[MLPrediction]) -> float:
        """Calculate weighted ensemble prediction from multiple models."""
        weighted_sum = 0.0
        total_weight = 0.0

        for prediction in predictions:
            weight = self.model_weights.get(prediction.model_type, 0.1)
            # Weight by model confidence as well
            effective_weight = weight * prediction.confidence
            weighted_sum += prediction.probability * effective_weight
            total_weight += effective_weight

        if total_weight == 0:
            return 0.0

        return min(weighted_sum / total_weight, 1.0)

    def _determine_confidence_level(
        self, probability: float, predictions: List[MLPrediction]
    ) -> str:
        """Determine overall confidence level for the prediction."""
        avg_confidence = (
            sum(p.confidence for p in predictions) / len(predictions)
            if predictions
            else 0.0
        )

        if (
            avg_confidence >= 0.8
            and len([p for p in predictions if p.confidence > 0.7]) >= 2
        ):
            return "HIGH"
        elif avg_confidence >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"


def test_ml_robustness() -> Dict[str, bool]:
    """
    Test ML model robustness against adversarial inputs.

    Returns:
        Dict[str, bool]: Test results for various attack scenarios
    """
    engine = MLPatternEngine()
    test_results = {}

    # Test adversarial inputs
    adversarial_inputs = [
        # Extremely long strings
        "a" * 10000,
        # Special characters
        "\x00\x01\x02\x03malicious",
        # Unicode attacks
        "𝕞𝕒𝕝𝕚𝕔𝕚𝕠𝕦𝕤",
        # SQL injection attempts
        "'; DROP TABLE packages;--",
        # Script injection
        "<script>alert('xss')</script>",
        # Path traversal
        "../../../etc/passwd",
        # Null bytes
        "package\x00.exe",
        # Extremely nested patterns
        "a-" * 1000,
        # Mathematical edge cases
        "package" + str(float("inf")),
        # Empty and whitespace
        "",
        "   ",
        "\n\t\r",
    ]

    print("Running ML robustness tests...")

    try:
        for i, malicious_input in enumerate(adversarial_inputs):
            test_name = f"adversarial_test_{i}"
            try:
                # Test naming classifier
                result = engine.naming_classifier.predict(malicious_input, "test")

                # Verify output is bounded and safe
                is_safe = (
                    0.0 <= result.confidence <= 1.0
                    and 0.0 <= result.probability <= 1.0
                    and isinstance(result.features_detected, list)
                    and len(result.features_detected) <= 100
                )
                test_results[test_name] = is_safe

            except Exception as e:
                # Any exception means the test failed
                test_results[test_name] = False
                print(f"Test {test_name} failed with: {type(e).__name__}")

        # Test semantic analyzer with malicious PackageInfo
        try:
            from types import SimpleNamespace

            malicious_package = SimpleNamespace(
                name="test" * 1000,
                description="<script>alert('xss')</script>" * 100,
                author="\x00malicious\x00author",
                version="1.0.0" * 100,
                homepage=None,
                repository=None,
                license=None,
                created_at="malicious_date",
                exists=True,
            )

            result = engine.semantic_analyzer.analyze_package_metadata(malicious_package)  # type: ignore
            test_results["semantic_adversarial"] = (
                0.0 <= result.confidence <= 1.0 and 0.0 <= result.probability <= 1.0
            )

        except Exception:
            test_results["semantic_adversarial"] = False

        # Test feature extraction robustness
        try:
            malicious_features = _robust_feature_extraction("malicious" * 1000)
            all_bounded = all(
                MIN_FEATURE_VALUE <= value <= MAX_FEATURE_VALUE
                for value in malicious_features.values()
            )
            test_results["feature_extraction_bounds"] = all_bounded

        except Exception:
            test_results["feature_extraction_bounds"] = False

        print(
            f"Robustness tests completed. Passed: {sum(test_results.values())}/{len(test_results)}"
        )
        return test_results

    except Exception as e:
        print(f"Critical error in robustness testing: {e}")
        return {"critical_error": False}


def get_ml_pattern_engine() -> MLPatternEngine:
    """
    Get a cached ML pattern engine instance with thread-safe singleton pattern.

    Features:
    - Thread-safe singleton implementation
    - TTL-based cache expiration (1 hour default)
    - Access count limits to prevent memory leaks
    - Automatic cleanup and recreation when needed
    - Proper error handling and fallback

    Returns:
        MLPatternEngine: Cached or new ML engine instance
    """
    global _ml_engine_instance, _ml_engine_created_at, _ml_engine_access_count

    with _ml_engine_lock:
        current_time = time.time()

        # Check if we need to create/recreate the instance
        should_recreate = (
            _ml_engine_instance is None
            or _ml_engine_created_at is None
            or (current_time - _ml_engine_created_at) > _ML_CACHE_TTL_SECONDS
            or _ml_engine_access_count > _ML_CACHE_MAX_ACCESS_COUNT
        )

        if should_recreate:
            try:
                # Clean up old instance if it exists
                if _ml_engine_instance is not None:
                    _cleanup_ml_engine_instance(_ml_engine_instance)

                # Create new instance
                _ml_engine_instance = MLPatternEngine()
                _ml_engine_created_at = current_time
                _ml_engine_access_count = 0

                get_error_handler().warning(
                    ErrorCategory.ML_MODEL,
                    f"Created new ML engine instance (reason: {'expired' if _ml_engine_created_at else 'first_time'})",
                    "ml_engine",
                    "get_ml_pattern_engine",
                    details={
                        "cache_age_seconds": current_time
                        - (_ml_engine_created_at or current_time),
                        "access_count": _ml_engine_access_count,
                    },
                )

            except Exception as e:
                get_error_handler().error(
                    ErrorCategory.ML_MODEL,
                    f"Failed to create ML engine instance: {e}",
                    "ml_engine",
                    "get_ml_pattern_engine",
                    exception=e,
                )
                # Fallback: create a basic instance without caching
                return MLPatternEngine()

        # Track access for cache management
        _ml_engine_access_count += 1

        # Return the cached instance (guaranteed to be non-None at this point)
        assert _ml_engine_instance is not None, "ML engine instance should not be None"
        return _ml_engine_instance


def _cleanup_ml_engine_instance(instance: MLPatternEngine) -> None:
    """
    Clean up ML engine instance to prevent memory leaks.

    Args:
        instance: ML engine instance to clean up
    """
    try:
        # Clear model references if they have cleanup methods
        if hasattr(instance, "naming_classifier"):
            _cleanup_model_instance(instance.naming_classifier)
        if hasattr(instance, "semantic_analyzer"):
            _cleanup_model_instance(instance.semantic_analyzer)
        if hasattr(instance, "behavioral_detector"):
            _cleanup_model_instance(instance.behavioral_detector)

        # Clear weights and other references
        if hasattr(instance, "model_weights"):
            instance.model_weights.clear()

    except Exception as e:
        get_error_handler().warning(
            ErrorCategory.ML_MODEL,
            f"Error during ML engine cleanup: {e}",
            "ml_engine",
            "_cleanup_ml_engine_instance",
            exception=e,
        )


def _cleanup_model_instance(model: Any) -> None:
    """Clean up individual ML model instance."""
    try:
        # Clear common model attributes
        attrs_to_clear = ["vocabulary", "feature_weights", "_cache", "patterns"]
        for attr in attrs_to_clear:
            if hasattr(model, attr):
                obj = getattr(model, attr)
                if hasattr(obj, "clear"):
                    obj.clear()
                elif isinstance(obj, (list, set)):
                    obj.clear()

    except Exception:
        pass  # Silent cleanup - don't propagate errors


def reset_ml_engine_cache() -> bool:
    """
    Reset the ML engine cache, forcing recreation on next access.

    Useful for testing or when configuration changes.

    Returns:
        bool: True if cache was reset successfully
    """
    global _ml_engine_instance, _ml_engine_created_at, _ml_engine_access_count

    with _ml_engine_lock:
        try:
            if _ml_engine_instance is not None:
                _cleanup_ml_engine_instance(_ml_engine_instance)

            _ml_engine_instance = None
            _ml_engine_created_at = None
            _ml_engine_access_count = 0

            get_error_handler().warning(
                ErrorCategory.ML_MODEL,
                "ML engine cache reset successfully",
                "ml_engine",
                "reset_ml_engine_cache",
            )
            return True

        except Exception as e:
            get_error_handler().error(
                ErrorCategory.ML_MODEL,
                f"Failed to reset ML engine cache: {e}",
                "ml_engine",
                "reset_ml_engine_cache",
                exception=e,
            )
            return False


def get_ml_engine_cache_stats() -> Dict[str, Any]:
    """
    Get statistics about the ML engine cache.

    Returns:
        Dict[str, Any]: Cache statistics including age, access count, memory info
    """
    global _ml_engine_instance, _ml_engine_created_at, _ml_engine_access_count

    with _ml_engine_lock:
        current_time = time.time()

        stats = {
            "is_cached": _ml_engine_instance is not None,
            "created_at": _ml_engine_created_at,
            "access_count": _ml_engine_access_count,
            "cache_ttl_seconds": _ML_CACHE_TTL_SECONDS,
            "max_access_count": _ML_CACHE_MAX_ACCESS_COUNT,
        }

        if _ml_engine_created_at is not None:
            stats.update(
                {
                    "age_seconds": current_time - _ml_engine_created_at,
                    "time_until_expiry": _ML_CACHE_TTL_SECONDS
                    - (current_time - _ml_engine_created_at),
                    "is_expired": (current_time - _ml_engine_created_at)
                    > _ML_CACHE_TTL_SECONDS,
                }
            )

        if _ml_engine_instance is not None:
            try:
                import sys

                stats["approximate_size_bytes"] = sys.getsizeof(_ml_engine_instance)
            except Exception:
                pass

        return stats


def configure_ml_engine_cache(
    ttl_seconds: Optional[int] = None, max_access_count: Optional[int] = None
) -> bool:
    """
    Configure ML engine cache parameters.

    Args:
        ttl_seconds: Time-to-live for cached instances (None = no change)
        max_access_count: Maximum access count before recreation (None = no change)

    Returns:
        bool: True if configuration was updated successfully
    """
    global _ML_CACHE_TTL_SECONDS, _ML_CACHE_MAX_ACCESS_COUNT

    try:
        if ttl_seconds is not None:
            if ttl_seconds <= 0:
                raise ValueError("TTL must be positive")
            _ML_CACHE_TTL_SECONDS = ttl_seconds

        if max_access_count is not None:
            if max_access_count <= 0:
                raise ValueError("Max access count must be positive")
            _ML_CACHE_MAX_ACCESS_COUNT = max_access_count

        get_error_handler().warning(
            ErrorCategory.CONFIGURATION,
            f"ML engine cache configured: TTL={_ML_CACHE_TTL_SECONDS}s, max_access={_ML_CACHE_MAX_ACCESS_COUNT}",
            "ml_engine",
            "configure_ml_engine_cache",
            details={
                "ttl_seconds": _ML_CACHE_TTL_SECONDS,
                "max_access_count": _ML_CACHE_MAX_ACCESS_COUNT,
            },
        )
        return True

    except Exception as e:
        get_error_handler().error(
            ErrorCategory.CONFIGURATION,
            f"Failed to configure ML engine cache: {e}",
            "ml_engine",
            "configure_ml_engine_cache",
            exception=e,
        )
        return False
