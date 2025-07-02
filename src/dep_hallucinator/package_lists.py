"""
Package allowlist/denylist management for Dep-Hallucinator.
"""

import fnmatch
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .error_handling import get_error_handler


class ListType(Enum):
    """Types of package lists."""

    ALLOWLIST = "allowlist"
    DENYLIST = "denylist"


class MatchType(Enum):
    """Types of package matching."""

    EXACT = "exact"
    PATTERN = "pattern"
    PREFIX = "prefix"


@dataclass(frozen=True)
class PackageListEntry:
    """Entry in a package list."""

    name: str
    match_type: MatchType = MatchType.EXACT
    ecosystems: Optional[Set[str]] = None
    reason: Optional[str] = None
    added_date: Optional[str] = None

    def __post_init__(self):
        """Initialize default values."""
        if self.added_date is None:
            object.__setattr__(
                self, "added_date", datetime.now(timezone.utc).isoformat()
            )

        # Include ALL supported ecosystems by default - this is critical for the fix
        if self.ecosystems is None:
            object.__setattr__(
                self, "ecosystems", {"pip", "npm", "maven", "crates", "go"}
            )

    def matches_package(self, package_name: str, ecosystem: str = "unknown") -> bool:
        """Check if this entry matches the given package."""
        # Check ecosystem filter
        if self.ecosystems and ecosystem not in self.ecosystems:
            return False

        # Check name pattern
        if self.match_type == MatchType.EXACT:
            return package_name.lower() == self.name.lower()
        elif self.match_type == MatchType.PATTERN:
            return fnmatch.fnmatch(package_name.lower(), self.name.lower())
        elif self.match_type == MatchType.PREFIX:
            return package_name.lower().startswith(self.name.lower())

        return False


class PackageListManager:
    """Manager for package allowlists and denylists."""

    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize package list manager."""
        self.error_handler = get_error_handler()

        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            self.config_dir = Path.home() / ".config" / "dep-hallucinator"

        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.allowlist_file = self.config_dir / "allowlist.json"
        self.denylist_file = self.config_dir / "denylist.json"

        self._allowlist: List[PackageListEntry] = []
        self._denylist: List[PackageListEntry] = []
        self._lists_loaded = False

        self._load_default_lists()

    def _load_default_lists(self):
        """Load default package lists."""
        # Default allowlist - popular packages across ecosystems
        default_allowlist = [
            # Python packages
            PackageListEntry(
                "requests", ecosystems={"pip"}, reason="Popular HTTP library"
            ),
            PackageListEntry(
                "numpy", ecosystems={"pip"}, reason="Popular scientific library"
            ),
            PackageListEntry(
                "pandas", ecosystems={"pip"}, reason="Popular data analysis library"
            ),
            # npm packages
            PackageListEntry(
                "express", ecosystems={"npm"}, reason="Popular web framework"
            ),
            PackageListEntry("react", ecosystems={"npm"}, reason="Popular UI library"),
            # Maven/Java packages
            PackageListEntry(
                "spring-core", ecosystems={"maven"}, reason="Popular Spring framework"
            ),
            PackageListEntry(
                "junit", ecosystems={"maven"}, reason="Popular testing framework"
            ),
            PackageListEntry(
                "log4j-core", ecosystems={"maven"}, reason="Popular logging library"
            ),
            # Rust packages
            PackageListEntry(
                "serde", ecosystems={"crates"}, reason="Popular serialization library"
            ),
            PackageListEntry(
                "tokio", ecosystems={"crates"}, reason="Popular async runtime"
            ),
            PackageListEntry(
                "clap", ecosystems={"crates"}, reason="Popular CLI argument parser"
            ),
            # Go packages
            PackageListEntry(
                "github.com/gin-gonic/gin",
                ecosystems={"go"},
                reason="Popular web framework",
            ),
            PackageListEntry(
                "github.com/gorilla/mux",
                ecosystems={"go"},
                reason="Popular HTTP router",
            ),
            PackageListEntry(
                "github.com/stretchr/testify",
                ecosystems={"go"},
                reason="Popular testing toolkit",
            ),
        ]

        # Default denylist - suspicious patterns for ALL ecosystems
        default_denylist = [
            # AI-generated patterns - apply to ALL ecosystems
            PackageListEntry(
                "ai-*",
                MatchType.PATTERN,
                reason="AI-prefixed packages often AI-generated",
            ),
            PackageListEntry(
                "smart-*",
                MatchType.PATTERN,
                reason="Smart-prefixed packages often AI-generated",
            ),
            PackageListEntry(
                "auto-*",
                MatchType.PATTERN,
                reason="Auto-prefixed packages often AI-generated",
            ),
            PackageListEntry(
                "ml-*",
                MatchType.PATTERN,
                reason="ML-prefixed packages often AI-generated",
            ),
            PackageListEntry(
                "chatgpt-*",
                MatchType.PATTERN,
                reason="ChatGPT-prefixed packages often AI-generated",
            ),
            PackageListEntry(
                "gpt-*",
                MatchType.PATTERN,
                reason="GPT-prefixed packages often AI-generated",
            ),
        ]

        self._allowlist.extend(default_allowlist)
        self._denylist.extend(default_denylist)
        self._lists_loaded = True

    def is_allowlisted(
        self, package_name: str, ecosystem: str = "unknown"
    ) -> Tuple[bool, Optional[PackageListEntry]]:
        """Check if a package is allowlisted."""
        if not self._lists_loaded:
            self._load_default_lists()

        for entry in self._allowlist:
            if entry.matches_package(package_name, ecosystem):
                return True, entry

        return False, None

    def is_denylisted(
        self, package_name: str, ecosystem: str = "unknown"
    ) -> Tuple[bool, Optional[PackageListEntry]]:
        """Check if a package is denylisted."""
        if not self._lists_loaded:
            self._load_default_lists()

        for entry in self._denylist:
            if entry.matches_package(package_name, ecosystem):
                return True, entry

        return False, None

    def add_to_allowlist(
        self,
        name: str,
        match_type: MatchType = MatchType.EXACT,
        reason: Optional[str] = None,
    ) -> bool:
        """Add a package to the allowlist."""
        entry = PackageListEntry(name=name, match_type=match_type, reason=reason)
        self._allowlist.append(entry)
        return True

    def add_to_denylist(
        self,
        name: str,
        match_type: MatchType = MatchType.EXACT,
        reason: Optional[str] = None,
    ) -> bool:
        """Add a package to the denylist."""
        entry = PackageListEntry(name=name, match_type=match_type, reason=reason)
        self._denylist.append(entry)
        return True

    def remove_from_allowlist(self, name: str, ecosystem: str = "unknown") -> bool:
        """Remove a package from the allowlist."""
        if not self._lists_loaded:
            self._load_default_lists()

        original_length = len(self._allowlist)
        self._allowlist = [
            entry
            for entry in self._allowlist
            if not entry.matches_package(name, ecosystem)
        ]

        return len(self._allowlist) < original_length

    def remove_from_denylist(self, name: str, ecosystem: str = "unknown") -> bool:
        """Remove a package from the denylist."""
        if not self._lists_loaded:
            self._load_default_lists()

        original_length = len(self._denylist)
        self._denylist = [
            entry
            for entry in self._denylist
            if not entry.matches_package(name, ecosystem)
        ]

        return len(self._denylist) < original_length

    def get_allowlist(self, ecosystem: Optional[str] = None) -> List[PackageListEntry]:
        """Get allowlist entries, optionally filtered by ecosystem."""
        if not self._lists_loaded:
            self._load_default_lists()

        if ecosystem:
            return [
                entry
                for entry in self._allowlist
                if not entry.ecosystems or ecosystem in entry.ecosystems
            ]
        return list(self._allowlist)

    def get_denylist(self, ecosystem: Optional[str] = None) -> List[PackageListEntry]:
        """Get denylist entries, optionally filtered by ecosystem."""
        if not self._lists_loaded:
            self._load_default_lists()

        if ecosystem:
            return [
                entry
                for entry in self._denylist
                if not entry.ecosystems or ecosystem in entry.ecosystems
            ]
        return list(self._denylist)


# Global instance
_package_list_manager: Optional[PackageListManager] = None


def get_package_list_manager() -> PackageListManager:
    """Get the global package list manager instance."""
    global _package_list_manager
    if _package_list_manager is None:
        _package_list_manager = PackageListManager()
    return _package_list_manager
