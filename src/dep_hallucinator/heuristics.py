"""
Heuristic analysis engine for detecting suspicious package registrations.

Implements algorithms to analyze package metadata and identify
potential malicious registrations of AI-hallucinated dependencies.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from enum import Enum
from typing import Any, Dict, List, Optional

from .cli_config import get_config
from .ml_engine import PatternAnalysisResult, get_ml_pattern_engine
from .registry_clients import PackageInfo


class HeuristicType(Enum):
    """Types of heuristic analysis."""

    PACKAGE_AGE = "package_age"
    DOWNLOAD_COUNT = "download_count"
    METADATA_COMPLETENESS = "metadata_completeness"
    NAMING_PATTERN = "naming_pattern"
    TYPOSQUATTING = "typosquatting"
    VERSION_ANALYSIS = "version_analysis"
    ML_PATTERN_ANALYSIS = "ml_pattern_analysis"


@dataclass(frozen=True)
class HeuristicResult:
    """Result of a single heuristic analysis."""

    heuristic_type: HeuristicType
    score: float  # 0.0 = legitimate, 1.0 = highly suspicious
    confidence: float  # 0.0 = low confidence, 1.0 = high confidence
    reasons: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HallucinationScore:
    """Complete heuristic analysis result for a package."""

    package_name: str
    overall_score: float  # Weighted combination of all heuristics
    risk_level: str  # HIGH, MEDIUM, LOW based on score
    heuristic_results: List[HeuristicResult] = field(default_factory=list)
    ml_analysis: Optional[PatternAnalysisResult] = None

    @property
    def is_suspicious(self) -> bool:
        """Check if the package is considered suspicious."""
        return self.overall_score >= 0.7

    @property
    def is_highly_suspicious(self) -> bool:
        """Check if the package is highly suspicious."""
        return self.overall_score >= 0.85


class HeuristicEngine:
    """
    Core engine for analyzing packages using multiple heuristics.

    Implements the RORO pattern: receives PackageInfo, returns HallucinationScore.
    Integrates traditional heuristics with advanced ML pattern recognition.
    """

    def __init__(self):
        """Initialize the heuristic engine with scoring weights."""
        # Get configuration
        config = get_config()

        # Weights for different heuristics (from config)
        self.heuristic_weights = config.heuristics.weights.copy()

        # Popular packages for typosquatting detection
        self.popular_packages = self._load_popular_packages()

        # ML pattern engine for advanced analysis
        self.ml_engine = get_ml_pattern_engine()

        # Weights for combining heuristics and ML (from config)
        self.heuristic_weight = config.ml.ensemble_heuristic_weight
        self.ml_weight = config.ml.ensemble_ml_weight

        # Store config for use in analysis methods
        self.config = config

    async def analyze_package(
        self, package_info: PackageInfo, registry_type: str = "unknown"
    ) -> HallucinationScore:
        """
        Analyze a package using all available heuristics and ML models.

        Args:
            package_info: Package information from registry
            registry_type: Type of registry (pypi, npm)

        Returns:
            HallucinationScore with overall assessment
        """
        if not package_info or not package_info.exists:
            # Package doesn't exist - this is handled by the scanner as CRITICAL
            return HallucinationScore(
                package_name=package_info.name if package_info else "unknown",
                overall_score=1.0,
                risk_level="CRITICAL",
            )

        # Run traditional heuristic analyses
        heuristic_results = []

        # Age analysis
        age_result = self._analyze_package_age(package_info)
        heuristic_results.append(age_result)

        # Download count analysis
        download_result = self._analyze_download_count(package_info, registry_type)
        heuristic_results.append(download_result)

        # Metadata completeness
        metadata_result = self._analyze_metadata_completeness(package_info)
        heuristic_results.append(metadata_result)

        # Naming pattern analysis
        naming_result = self._analyze_naming_pattern(package_info.name, registry_type)
        heuristic_results.append(naming_result)

        # Typosquatting detection
        typo_result = self._analyze_typosquatting(package_info.name, registry_type)
        heuristic_results.append(typo_result)

        # Version analysis
        version_result = self._analyze_version_pattern(package_info)
        heuristic_results.append(version_result)

        # ML pattern analysis
        ml_analysis = await self.ml_engine.analyze_package(package_info, registry_type)
        ml_result = self._convert_ml_to_heuristic(ml_analysis)
        heuristic_results.append(ml_result)

        # Calculate weighted traditional heuristic score
        traditional_score = self._calculate_weighted_score(
            heuristic_results[:-1]
        )  # Exclude ML result

        # Combine traditional heuristics with ML prediction
        overall_score = self._combine_heuristic_and_ml_scores(
            traditional_score, ml_analysis.overall_ai_probability
        )

        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)

        return HallucinationScore(
            package_name=package_info.name,
            overall_score=overall_score,
            risk_level=risk_level,
            heuristic_results=heuristic_results,
            ml_analysis=ml_analysis,
        )

    def _convert_ml_to_heuristic(
        self, ml_analysis: PatternAnalysisResult
    ) -> HeuristicResult:
        """Convert ML analysis result to heuristic result format."""
        reasons = []

        if ml_analysis.is_highly_likely_ai_generated:
            reasons.append(
                f"ML models indicate high probability ({int(ml_analysis.overall_ai_probability * 100)}%) of AI generation"
            )
        elif ml_analysis.is_likely_ai_generated:
            reasons.append(
                f"ML models indicate likely AI generation ({int(ml_analysis.overall_ai_probability * 100)}%)"
            )
        else:
            reasons.append("ML models indicate low probability of AI generation")

        # Add specific pattern detections
        if ml_analysis.detected_patterns:
            pattern_summary = ", ".join(
                ml_analysis.detected_patterns[:3]
            )  # Limit to first 3
            if len(ml_analysis.detected_patterns) > 3:
                pattern_summary += f" (+{len(ml_analysis.detected_patterns) - 3} more)"
            reasons.append(f"Detected patterns: {pattern_summary}")

        # Calculate confidence based on ML confidence level
        confidence_map = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}
        confidence = confidence_map.get(ml_analysis.confidence_level, 0.6)

        return HeuristicResult(
            heuristic_type=HeuristicType.ML_PATTERN_ANALYSIS,
            score=ml_analysis.overall_ai_probability,
            confidence=confidence,
            reasons=reasons,
            evidence={
                "ml_confidence": ml_analysis.confidence_level,
                "detected_patterns": ml_analysis.detected_patterns,
                "model_count": len(ml_analysis.model_predictions),
            },
        )

    def _combine_heuristic_and_ml_scores(
        self, heuristic_score: float, ml_score: float
    ) -> float:
        """Combine traditional heuristic score with ML prediction."""
        # Weighted combination
        combined_score = (heuristic_score * self.heuristic_weight) + (
            ml_score * self.ml_weight
        )

        # Apply ensemble adjustment - if both agree, boost confidence
        agreement_factor = 1.0
        if abs(heuristic_score - ml_score) < 0.2:  # Scores are close
            if heuristic_score > 0.7 and ml_score > 0.7:  # Both high
                agreement_factor = 1.1
            elif heuristic_score < 0.3 and ml_score < 0.3:  # Both low
                agreement_factor = 0.9

        return min(combined_score * agreement_factor, 1.0)

    def _analyze_package_age(self, package_info: PackageInfo) -> HeuristicResult:
        """Analyze package age - very new packages are suspicious."""
        if not package_info.created_at:
            return HeuristicResult(
                heuristic_type=HeuristicType.PACKAGE_AGE,
                score=0.3,
                confidence=0.5,
                reasons=["Package creation date unavailable"],
                evidence={"created_at": None},
            )

        try:
            # Parse creation date (handle different formats)
            if "T" in package_info.created_at:
                created_date = datetime.fromisoformat(
                    package_info.created_at.replace("Z", "+00:00")
                )
            else:
                created_date = datetime.fromisoformat(package_info.created_at)

            now = (
                datetime.now(created_date.tzinfo)
                if created_date.tzinfo
                else datetime.now()
            )
            age_days = (now - created_date).days

            # Age scoring: newer = more suspicious
            if age_days < 1:
                score = 0.95
                reasons = ["Package created within 24 hours"]
            elif age_days < 7:
                score = 0.85
                reasons = ["Package created within the last week"]
            elif age_days < 30:
                score = 0.70
                reasons = ["Package created within the last month"]
            elif age_days < 90:
                score = 0.45
                reasons = ["Package created within the last 3 months"]
            elif age_days < 365:
                score = 0.25
                reasons = ["Package less than 1 year old"]
            else:
                score = 0.10
                reasons = ["Package is well-established"]

            return HeuristicResult(
                heuristic_type=HeuristicType.PACKAGE_AGE,
                score=score,
                confidence=0.9,
                reasons=reasons,
                evidence={"age_days": age_days, "created_at": package_info.created_at},
            )

        except (ValueError, TypeError) as e:
            return HeuristicResult(
                heuristic_type=HeuristicType.PACKAGE_AGE,
                score=0.3,
                confidence=0.3,
                reasons=[f"Could not parse creation date: {str(e)}"],
                evidence={"created_at": package_info.created_at, "error": str(e)},
            )

    def _analyze_download_count(
        self, package_info: PackageInfo, registry_type: str
    ) -> HeuristicResult:
        """Analyze download statistics."""
        download_count = package_info.download_count

        if download_count is None:
            return HeuristicResult(
                heuristic_type=HeuristicType.DOWNLOAD_COUNT,
                score=0.4,
                confidence=0.5,
                reasons=["Download statistics unavailable"],
                evidence={"download_count": None},
            )

        # Different thresholds for different registries
        if registry_type == "pypi":
            thresholds = [
                (0, 0.95),
                (10, 0.85),
                (100, 0.65),
                (1000, 0.45),
                (10000, 0.25),
            ]
        else:
            thresholds = [
                (0, 0.95),
                (50, 0.85),
                (500, 0.65),
                (5000, 0.45),
                (50000, 0.25),
            ]

        score = 0.10
        reasons = []

        for threshold, threshold_score in thresholds:
            if download_count <= threshold:
                score = threshold_score
                if download_count == 0:
                    reasons = ["Package has zero downloads"]
                elif download_count <= thresholds[1][0]:
                    reasons = [f"Very low download count: {download_count}"]
                else:
                    reasons = [f"Low download count: {download_count}"]
                break
        else:
            reasons = [f"High download count: {download_count}"]

        return HeuristicResult(
            heuristic_type=HeuristicType.DOWNLOAD_COUNT,
            score=score,
            confidence=0.8,
            reasons=reasons,
            evidence={"download_count": download_count},
        )

    def _analyze_metadata_completeness(
        self, package_info: PackageInfo
    ) -> HeuristicResult:
        """Analyze metadata completeness."""
        missing_fields = []
        score = 0.0

        if not package_info.author or package_info.author.strip() == "":
            missing_fields.append("author")
            score += 0.25

        if not package_info.description or package_info.description.strip() == "":
            missing_fields.append("description")
            score += 0.20

        if not package_info.homepage and not package_info.repository:
            missing_fields.append("homepage/repository")
            score += 0.25

        if not package_info.license or package_info.license.strip() == "":
            missing_fields.append("license")
            score += 0.15

        score = min(score, 1.0)

        reasons = []
        if missing_fields:
            reasons.append(f"Missing metadata: {', '.join(missing_fields)}")
        else:
            reasons.append("Metadata appears complete")

        return HeuristicResult(
            heuristic_type=HeuristicType.METADATA_COMPLETENESS,
            score=score,
            confidence=0.85,
            reasons=reasons,
            evidence={"missing_fields": missing_fields},
        )

    def _analyze_naming_pattern(
        self, package_name: str, registry_type: str
    ) -> HeuristicResult:
        """Analyze naming patterns typical of AI-generated names."""
        score = 0.0
        patterns_detected = []

        name_lower = package_name.lower()

        # AI-typical patterns
        ai_patterns = [
            (r"(smart|auto|ai|ml|intelligent|advanced)-.*", "AI-prefixed name"),
            (
                r".*-(helper|utils|tools|lib|core|pro|advanced)$",
                "Generic utility suffix",
            ),
            (
                r".*-(generator|processor|analyzer|validator)$",
                "AI-typical action suffix",
            ),
        ]

        for pattern, description in ai_patterns:
            if re.match(pattern, name_lower):
                score += 0.15
                patterns_detected.append(description)

        # Generic words
        generic_words = ["data", "text", "api", "web", "utils", "tools"]
        word_count = len([word for word in generic_words if word in name_lower])
        if word_count >= 2:
            score += 0.20
            patterns_detected.append(f"Contains {word_count} generic terms")

        # Excessive separators
        separator_count = name_lower.count("-") + name_lower.count("_")
        if separator_count >= 3:
            score += 0.15
            patterns_detected.append("Excessive separators")

        score = min(score, 1.0)

        reasons = []
        if patterns_detected:
            reasons = [f"AI-typical patterns: {', '.join(patterns_detected)}"]
        else:
            reasons = ["No suspicious naming patterns"]

        return HeuristicResult(
            heuristic_type=HeuristicType.NAMING_PATTERN,
            score=score,
            confidence=0.75,
            reasons=reasons,
            evidence={"patterns": patterns_detected},
        )

    def _analyze_typosquatting(
        self, package_name: str, registry_type: str
    ) -> HeuristicResult:
        """Detect potential typosquatting."""
        score = 0.0
        similar_packages = []

        popular_list = self.popular_packages.get(registry_type, [])

        for popular_pkg in popular_list:
            similarity = SequenceMatcher(
                None, package_name.lower(), popular_pkg.lower()
            ).ratio()

            if 0.7 <= similarity < 1.0:
                edit_distance = self._calculate_edit_distance(
                    package_name.lower(), popular_pkg.lower()
                )

                if edit_distance <= 2:
                    score += 0.30
                    similar_packages.append((popular_pkg, similarity))
                elif edit_distance <= 3:
                    score += 0.20
                    similar_packages.append((popular_pkg, similarity))

        score = min(score, 1.0)

        reasons = []
        if similar_packages:
            top_similar = similar_packages[0]
            reasons.append(
                f"Similar to '{top_similar[0]}' (similarity: {top_similar[1]:.2f})"
            )
        else:
            reasons = ["No typosquatting detected"]

        return HeuristicResult(
            heuristic_type=HeuristicType.TYPOSQUATTING,
            score=score,
            confidence=0.80,
            reasons=reasons,
            evidence={"similar_packages": similar_packages},
        )

    def _analyze_version_pattern(self, package_info: PackageInfo) -> HeuristicResult:
        """Analyze version patterns."""
        if not package_info.version:
            return HeuristicResult(
                heuristic_type=HeuristicType.VERSION_ANALYSIS,
                score=0.3,
                confidence=0.5,
                reasons=["No version information"],
                evidence={"version": None},
            )

        score = 0.0
        reasons = []
        version = package_info.version.strip()

        # Suspicious patterns
        if version in ["1.0.0", "0.1.0", "0.0.1"]:
            score += 0.20
            reasons.append("Initial version number")

        if re.match(r"^0\.0\.\d+$", version):
            score += 0.15
            reasons.append("Pre-release pattern")

        if not reasons:
            reasons = ["Version pattern normal"]

        return HeuristicResult(
            heuristic_type=HeuristicType.VERSION_ANALYSIS,
            score=min(score, 1.0),
            confidence=0.70,
            reasons=reasons,
            evidence={"version": version},
        )

    def _calculate_weighted_score(
        self, heuristic_results: List[HeuristicResult]
    ) -> float:
        """Calculate weighted overall score."""
        total_score = 0.0
        total_weight = 0.0

        for result in heuristic_results:
            # Use the enum value (string) as the key
            weight = self.heuristic_weights.get(result.heuristic_type.value, 0.0)
            effective_weight = weight * result.confidence
            total_score += result.score * effective_weight
            total_weight += effective_weight

        if total_weight == 0:
            return 0.0

        return min(total_score / total_weight, 1.0)

    def _determine_risk_level(self, overall_score: float) -> str:
        """Determine risk level based on score."""
        if overall_score >= 0.85:
            return "HIGH"
        elif overall_score >= 0.60:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_edit_distance(self, str1: str, str2: str) -> int:
        """Calculate Levenshtein distance."""
        if len(str1) < len(str2):
            return self._calculate_edit_distance(str2, str1)

        if len(str2) == 0:
            return len(str1)

        previous_row = list(range(len(str2) + 1))
        for i, c1 in enumerate(str1):
            current_row = [i + 1]
            for j, c2 in enumerate(str2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _load_popular_packages(self) -> Dict[str, List[str]]:
        """Load popular packages for typosquatting detection."""
        return {
            "pypi": [
                "requests",
                "urllib3",
                "certifi",
                "click",
                "flask",
                "django",
                "numpy",
                "pandas",
                "scipy",
                "matplotlib",
                "pillow",
                "boto3",
                "pytest",
                "setuptools",
                "wheel",
                "pip",
                "jinja2",
                "six",
            ],
            "npm": [
                "lodash",
                "chalk",
                "debug",
                "react",
                "vue",
                "express",
                "axios",
                "jquery",
                "bootstrap",
                "webpack",
                "babel",
                "eslint",
                "typescript",
                "jest",
                "mocha",
                "left-pad",
                "is-array",
                "moment",
            ],
        }


def get_heuristic_engine() -> HeuristicEngine:
    """Factory function to create a heuristic engine."""
    return HeuristicEngine()
