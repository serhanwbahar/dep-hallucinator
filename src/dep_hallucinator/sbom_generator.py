"""SBOM generation for supply chain security."""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .error_handling import ErrorCategory, get_error_handler
from .scanner import RiskLevel, ScanResult, SecurityFinding


class SBOMFormat(Enum):
    """Supported SBOM formats."""

    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"


@dataclass(frozen=True)
class SBOMComponent:
    """A component in the SBOM."""

    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    license: Optional[str] = None
    author: Optional[str] = None
    description: Optional[str] = None
    repository: Optional[str] = None
    download_location: Optional[str] = None
    signature_verified: Optional[bool] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_level: Optional[str] = None
    exists_in_registry: Optional[bool] = None


class SBOMGenerator:
    """Generates Software Bill of Materials in multiple formats."""

    def __init__(self):
        self.error_handler = get_error_handler()

    def generate_sbom(
        self,
        scan_result: ScanResult,
        source_file: str,
        sbom_format: SBOMFormat = SBOMFormat.SPDX,
    ) -> Dict[str, Any]:
        """Generate SBOM from scan results."""
        try:
            components = self._extract_components_from_scan(scan_result)

            if sbom_format == SBOMFormat.SPDX:
                return self._generate_spdx_sbom(components, source_file)
            elif sbom_format == SBOMFormat.CYCLONEDX:
                return self._generate_cyclonedx_sbom(components, source_file)
            else:
                raise ValueError(f"Unsupported SBOM format: {sbom_format}")

        except Exception as e:
            self.error_handler.error(
                ErrorCategory.VALIDATION,
                f"Failed to generate SBOM: {e}",
                "sbom_generator",
                "generate_sbom",
                exception=e,
            )
            raise

    def _extract_components_from_scan(
        self, scan_result: ScanResult
    ) -> List[SBOMComponent]:
        """Extract SBOM components from scan results."""
        components = []

        for finding in scan_result.findings:
            component = self._create_component_from_finding(finding)
            components.append(component)

        return components

    def _create_component_from_finding(self, finding: SecurityFinding) -> SBOMComponent:
        """Create SBOM component from security finding."""
        dependency = finding.dependency
        registry_result = finding.registry_result
        package_info = registry_result.package_info if registry_result else None

        # Generate Package URL (PURL)
        purl = self._generate_purl(dependency, registry_result)

        # Extract vulnerability information
        vulnerabilities = self._extract_vulnerabilities_from_finding(finding)

        return SBOMComponent(
            name=dependency.name,
            version=dependency.version,
            purl=purl,
            license=package_info.license if package_info else None,
            author=package_info.author if package_info else None,
            description=package_info.description if package_info else None,
            repository=package_info.repository if package_info else None,
            download_location=self._get_download_location(dependency, registry_result),
            signature_verified=finding.signature_verified,
            vulnerabilities=vulnerabilities,
            risk_level=finding.risk_level.value,
            exists_in_registry=package_info.exists if package_info else False,
        )

    def _generate_purl(self, dependency, registry_result) -> str:
        """Generate Package URL (PURL) for the dependency."""
        registry_type = registry_result.registry_type if registry_result else "pypi"

        purl_type_mapping = {
            "pypi": "pypi",
            "npm": "npm",
            "maven": "maven",
            "nuget": "nuget",
        }

        purl_type = purl_type_mapping.get(registry_type, "generic")

        purl = f"pkg:{purl_type}/{dependency.name}"
        if dependency.version:
            purl += f"@{dependency.version}"

        return purl

    def _extract_vulnerabilities_from_finding(
        self, finding: SecurityFinding
    ) -> List[Dict[str, Any]]:
        """Extract vulnerability information from security finding."""
        vulnerabilities = []

        if finding.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            vuln_id = (
                f"DEP-HALL-{finding.dependency.name.upper()}-{finding.risk_level.value}"
            )

            vulnerability = {
                "id": vuln_id,
                "source": "dep-hallucinator",
                "severity": finding.risk_level.value.lower(),
                "title": f"Dependency Confusion Risk: {finding.dependency.name}",
                "description": (
                    " | ".join(finding.reasons)
                    if finding.reasons
                    else "Package security risk detected"
                ),
                "recommendations": finding.recommendations or [],
                "published": datetime.now(timezone.utc).isoformat(),
                "updated": datetime.now(timezone.utc).isoformat(),
            }

            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _get_download_location(self, dependency, registry_result) -> str:
        """Get download location for the dependency."""
        if not registry_result:
            return "NOASSERTION"

        registry_type = registry_result.registry_type

        if registry_type == "pypi":
            return f"https://pypi.org/project/{dependency.name}/"
        elif registry_type == "npm":
            return f"https://www.npmjs.com/package/{dependency.name}"
        else:
            return "NOASSERTION"

    def _generate_spdx_sbom(
        self, components: List[SBOMComponent], source_file: str
    ) -> Dict[str, Any]:
        """Generate SPDX format SBOM."""
        document_id = str(uuid.uuid4())
        creation_time = datetime.now(timezone.utc).isoformat()

        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": Path(source_file).stem,
            "documentNamespace": f"https://dep-hallucinator.dev/sbom/{document_id}",
            "creationInfo": {
                "created": creation_time,
                "creators": ["Tool: dep-hallucinator"],
            },
            "packages": [],
            "relationships": [],
        }

        # Add root package
        root_package = {
            "SPDXID": "SPDXRef-Package-Root",
            "name": Path(source_file).stem,
            "downloadLocation": f"file://{source_file}",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        spdx_doc["packages"].append(root_package)

        # Add dependency packages
        for i, component in enumerate(components):
            package_id = f"SPDXRef-Package-{i+1}"

            package = {
                "SPDXID": package_id,
                "name": component.name,
                "downloadLocation": component.download_location or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": component.license or "NOASSERTION",
                "licenseDeclared": component.license or "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [],
            }

            if component.version:
                package["versionInfo"] = component.version

            if component.purl:
                package["externalRefs"].append(
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": component.purl,
                    }
                )

            # Add security annotations
            if component.risk_level:
                package["annotations"] = [
                    {
                        "annotationType": "REVIEW",
                        "annotator": "Tool: dep-hallucinator",
                        "annotationDate": creation_time,
                        "annotationComment": f"Risk Level: {component.risk_level}",
                    }
                ]

            spdx_doc["packages"].append(package)

            # Add relationship
            spdx_doc["relationships"].append(
                {
                    "spdxElementId": "SPDXRef-Package-Root",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package_id,
                }
            )

        return spdx_doc

    def _generate_cyclonedx_sbom(
        self, components: List[SBOMComponent], source_file: str
    ) -> Dict[str, Any]:
        """Generate CycloneDX format SBOM."""
        document_id = str(uuid.uuid4())
        creation_time = datetime.now(timezone.utc).isoformat()

        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{document_id}",
            "version": 1,
            "metadata": {
                "timestamp": creation_time,
                "tools": [
                    {
                        "vendor": "dep-hallucinator",
                        "name": "dep-hallucinator",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root-component",
                    "name": Path(source_file).stem,
                    "version": "1.0.0",
                },
            },
            "components": [],
            "vulnerabilities": [],
        }

        # Add components
        for component in components:
            comp_ref = (
                f"pkg:{component.purl}"
                if component.purl
                else f"component-{component.name}"
            )

            cyclonedx_component = {
                "type": "library",
                "bom-ref": comp_ref,
                "name": component.name,
                "purl": component.purl,
            }

            if component.version:
                cyclonedx_component["version"] = component.version

            if component.description:
                cyclonedx_component["description"] = component.description

            if component.license:
                cyclonedx_component["licenses"] = [
                    {"license": {"name": component.license}}
                ]

            if component.author:
                cyclonedx_component["author"] = component.author

            # Add security properties
            properties = []

            if component.risk_level:
                properties.append(
                    {
                        "name": "dep-hallucinator:risk-level",
                        "value": component.risk_level,
                    }
                )

            if component.exists_in_registry is not None:
                properties.append(
                    {
                        "name": "dep-hallucinator:exists-in-registry",
                        "value": str(component.exists_in_registry).lower(),
                    }
                )

            if component.signature_verified is not None:
                properties.append(
                    {
                        "name": "dep-hallucinator:signature-verified",
                        "value": str(component.signature_verified).lower(),
                    }
                )

            if properties:
                cyclonedx_component["properties"] = properties

            cyclonedx_doc["components"].append(cyclonedx_component)

            # Add vulnerabilities
            for vuln in component.vulnerabilities:
                cyclonedx_vuln = {
                    "bom-ref": f"vuln-{vuln['id']}",
                    "id": vuln["id"],
                    "source": {
                        "name": vuln["source"],
                        "url": "https://github.com/serhanwbahar/dep-hallucinator",
                    },
                    "ratings": [
                        {
                            "source": {"name": vuln["source"]},
                            "severity": vuln["severity"],
                            "method": "other",
                        }
                    ],
                    "description": vuln["description"],
                    "published": vuln["published"],
                    "updated": vuln["updated"],
                    "affects": [{"ref": comp_ref}],
                }

                cyclonedx_doc["vulnerabilities"].append(cyclonedx_vuln)

        return cyclonedx_doc

    def save_sbom(self, sbom_doc: Dict[str, Any], output_path: str) -> None:
        """Save SBOM document to file."""
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(sbom_doc, f, indent=2, ensure_ascii=False)

        except Exception as e:
            self.error_handler.error(
                ErrorCategory.FILESYSTEM,
                f"Failed to save SBOM: {e}",
                "sbom_generator",
                "save_sbom",
                exception=e,
            )
            raise


def get_sbom_generator() -> SBOMGenerator:
    """Factory function to get SBOM generator instance."""
    return SBOMGenerator()


def generate_sbom_from_scan(
    scan_result: ScanResult,
    source_file: str,
    output_path: str,
    sbom_format: SBOMFormat = SBOMFormat.SPDX,
) -> None:
    """Convenience function to generate and save SBOM from scan results."""
    generator = get_sbom_generator()
    sbom_doc = generator.generate_sbom(scan_result, source_file, sbom_format)
    generator.save_sbom(sbom_doc, output_path)
