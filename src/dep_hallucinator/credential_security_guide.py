"""
Credential Security Guide for Dep-Hallucinator

This module provides comprehensive guidance on secure credential management
for private registries and API key protection.
"""

import json
import os
import stat
from pathlib import Path
from typing import Dict, List


class CredentialSecurityGuide:
    """
    Comprehensive guide for secure credential management.

    Provides best practices, validation, and setup assistance for
    secure API key and credential storage.
    """

    @staticmethod
    def get_security_best_practices() -> Dict[str, List[str]]:
        """
        Get comprehensive security best practices for credentials.

        Returns:
            Dict[str, List[str]]: Categorized security recommendations
        """
        return {
            "Environment Variables": [
                "Use environment variables for CI/CD and production deployments",
                "Never commit .env files to version control",
                "Use prefixed variable names (DEP_HALLUCINATOR_*, PYPI_*, NPM_*)",
                "Validate environment variables before use",
                "Use secure environment variable injection in containers",
            ],
            "Credential Files": [
                "Store credential files outside of project directories",
                "Use restrictive file permissions (600 or 700)",
                "Encrypt credential files at rest when possible",
                "Use secure directories (~/.config/dep-hallucinator/)",
                "Never commit credential files to version control",
            ],
            "API Key Security": [
                "Use tokens with minimal required permissions",
                "Rotate API keys regularly (monthly/quarterly)",
                "Use different keys for different environments",
                "Monitor API key usage and access logs",
                "Revoke compromised keys immediately",
            ],
            "Private Registry Security": [
                "Use registry-specific authentication methods",
                "Validate registry SSL certificates",
                "Use secure transport (HTTPS) for all communications",
                "Implement proper authentication headers",
                "Sanitize URLs in logs to prevent credential exposure",
            ],
            "Development Security": [
                "Use separate credentials for development vs production",
                "Never hardcode credentials in source code",
                "Use secure credential injection for testing",
                "Implement credential validation and sanitization",
                "Use proper error handling to prevent information leakage",
            ],
        }

    @staticmethod
    def create_secure_credentials_file(
        file_path: Path, registry_configs: Dict[str, Dict[str, str]]
    ) -> bool:
        """
        Create a securely configured credentials file.

        Args:
            file_path: Path where to create the credentials file
            registry_configs: Registry configurations to store

        Returns:
            bool: True if file was created successfully
        """
        try:
            # Ensure parent directory exists with secure permissions
            file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Create credentials structure
            credentials_data = {
                "version": "1.0",
                "created_with": "dep-hallucinator-credential-manager",
                "security_note": "This file contains sensitive credentials. Keep it secure!",
                "registries": registry_configs,
            }

            # Write file with secure permissions
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(credentials_data, f, indent=2)

            # Set restrictive permissions (readable only by owner)
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # 600

            return True

        except (OSError, json.JSONEncodeError, PermissionError) as e:
            print(f"Error creating credentials file: {e}")
            return False

    @staticmethod
    def validate_credential_file_security(file_path: Path) -> Dict[str, bool]:
        """
        Validate security of a credential file.

        Args:
            file_path: Path to credential file to validate

        Returns:
            Dict[str, bool]: Security validation results
        """
        results = {
            "file_exists": False,
            "proper_permissions": False,
            "not_in_project_dir": False,
            "valid_json": False,
            "has_required_structure": False,
            "secure_location": False,
        }

        if not file_path.exists():
            return results

        results["file_exists"] = True

        try:
            # Check file permissions
            file_stat = file_path.stat()
            # Check if file is readable by group or others (security risk)
            if not (file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH)):
                results["proper_permissions"] = True

            # Check if file is not in current working directory
            if not str(file_path).startswith(str(Path.cwd())):
                results["not_in_project_dir"] = True

            # Check if file is in a secure location
            secure_locations = [
                str(Path.home() / ".config" / "dep-hallucinator"),
                str(Path.home() / ".dep-hallucinator"),
            ]
            if any(str(file_path).startswith(loc) for loc in secure_locations):
                results["secure_location"] = True

            # Validate JSON structure
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)
                results["valid_json"] = True

                if isinstance(data, dict) and "registries" in data:
                    results["has_required_structure"] = True

        except (json.JSONDecodeError, PermissionError, OSError):
            pass

        return results

    @staticmethod
    def get_credential_file_template() -> Dict[str, any]:
        """
        Get a template for credential files.

        Returns:
            Dict[str, any]: Template structure for credential files
        """
        return {
            "version": "1.0",
            "created_with": "dep-hallucinator",
            "security_note": "Keep this file secure! It contains sensitive API credentials.",
            "registries": {
                "pypi": {
                    "base_url": "https://pypi.org/pypi",
                    "auth_type": "bearer",
                    "token": "pypi-AgEIcHlwaS5vcmcCJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMAACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0AAAYgO...",
                    "comment": "PyPI API token for package publishing/access",
                },
                "npm": {
                    "base_url": "https://registry.npmjs.org",
                    "auth_type": "bearer",
                    "token": "npm_1234567890abcdef1234567890abcdef12345678",
                    "comment": "npm registry token for package access",
                },
                "private_pypi": {
                    "base_url": "https://private-pypi.company.com/simple",
                    "auth_type": "basic",
                    "token": "dXNlcm5hbWU6cGFzc3dvcmQ=",  # base64 encoded username:password
                    "comment": "Private PyPI server with basic authentication",
                },
                "artifactory": {
                    "base_url": "https://company.jfrog.io/artifactory/api/pypi/pypi-local",
                    "auth_type": "api_key",
                    "api_key": "AKCp8jQ8FVZ6oDswxoE1kMfKBjVgkBSp4bqbJtHn2i5vW8yNjxK",
                    "comment": "JFrog Artifactory with API key authentication",
                },
            },
        }

    @staticmethod
    def get_environment_variable_guide() -> Dict[str, str]:
        """
        Get guide for environment variable setup.

        Returns:
            Dict[str, str]: Environment variable names and descriptions
        """
        return {
            "PYPI_API_TOKEN": "PyPI API token for package publishing/access",
            "NPM_AUTH_TOKEN": "npm registry authentication token",
            "NPM_TOKEN": "Alternative npm token variable name",
            "PYPI_TOKEN": "Alternative PyPI token variable name",
            "DEP_HALLUCINATOR_PYPI_TOKEN": "Tool-specific PyPI token",
            "DEP_HALLUCINATOR_NPM_TOKEN": "Tool-specific npm token",
            "REGISTRY_TOKEN": "Generic registry token for private registries",
        }

    @staticmethod
    def generate_secure_setup_instructions() -> str:
        """
        Generate comprehensive setup instructions for secure credentials.

        Returns:
            str: Formatted setup instructions
        """
        return """
🔐 SECURE CREDENTIAL SETUP GUIDE
================================

1. ENVIRONMENT VARIABLES (Recommended for CI/CD)
   ---------------------------------------------
   # For PyPI access:
   export PYPI_API_TOKEN="pypi-AgEIcHlwaS5vcmcCJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMAACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0AAAYgO..."
   
   # For npm access:
   export NPM_AUTH_TOKEN="npm_1234567890abcdef1234567890abcdef12345678"
   
   # Tool-specific variables:
   export DEP_HALLUCINATOR_PYPI_TOKEN="your-pypi-token"
   export DEP_HALLUCINATOR_NPM_TOKEN="your-npm-token"

2. CREDENTIAL FILES (Recommended for local development)
   ----------------------------------------------------
   # Create secure directory:
   mkdir -p ~/.config/dep-hallucinator
   chmod 700 ~/.config/dep-hallucinator
   
   # Create credentials file:
   touch ~/.config/dep-hallucinator/credentials.json
   chmod 600 ~/.config/dep-hallucinator/credentials.json
   
   # Edit with your preferred editor and add credential configuration

3. SECURITY CHECKLIST
   ------------------
   ✅ Never commit credentials to version control
   ✅ Use restrictive file permissions (600/700)
   ✅ Store credentials outside project directories  
   ✅ Use environment variables in CI/CD pipelines
   ✅ Rotate credentials regularly
   ✅ Use minimal required permissions
   ✅ Monitor credential usage and access
   ✅ Revoke compromised credentials immediately

4. PRIVATE REGISTRY CONFIGURATION
   -------------------------------
   For private PyPI servers, npm registries, or Artifactory:
   
   {
     "registries": {
       "private_pypi": {
         "base_url": "https://private-pypi.company.com/simple",
         "auth_type": "basic",
         "token": "base64-encoded-username:password"
       },
       "private_npm": {
         "base_url": "https://npm.company.com",
         "auth_type": "bearer",
         "token": "your-private-npm-token"
       }
     }
   }

5. CI/CD INTEGRATION
   ------------------
   # GitHub Actions example:
   env:
     PYPI_API_TOKEN: ${{ secrets.PYPI_API_TOKEN }}
     NPM_AUTH_TOKEN: ${{ secrets.NPM_AUTH_TOKEN }}
   
   # GitLab CI example:
   variables:
     PYPI_API_TOKEN: $PYPI_API_TOKEN
     NPM_AUTH_TOKEN: $NPM_AUTH_TOKEN

6. TROUBLESHOOTING
   ---------------
   - Check file permissions: ls -la ~/.config/dep-hallucinator/
   - Validate JSON syntax: python -m json.tool credentials.json
   - Test environment variables: echo $PYPI_API_TOKEN
   - Review logs for authentication errors
   - Verify token permissions and expiration

For more information, see: https://github.com/serhanwbahar/dep-hallucinator/blob/main/SECURITY.md
"""

    @staticmethod
    def perform_security_audit() -> Dict[str, any]:
        """
        Perform a security audit of current credential configuration.

        Returns:
            Dict[str, any]: Audit results with recommendations
        """
        audit_results = {
            "timestamp": "2024-01-01T00:00:00Z",
            "environment_variables": {},
            "credential_files": {},
            "security_score": 0,
            "recommendations": [],
        }

        # Check environment variables
        env_vars = CredentialSecurityGuide.get_environment_variable_guide()
        for var_name in env_vars.keys():
            if var_name in os.environ:
                audit_results["environment_variables"][var_name] = {
                    "present": True,
                    "length": len(os.environ[var_name]),
                    "secure": len(os.environ[var_name]) > 20,  # Basic length check
                }

        # Check credential files
        credential_locations = [
            Path.home() / ".config" / "dep-hallucinator" / "credentials.json",
            Path.home() / ".dep-hallucinator-credentials.json",
            Path.cwd() / ".dep-hallucinator-credentials.json",
        ]

        for file_path in credential_locations:
            if file_path.exists():
                validation = CredentialSecurityGuide.validate_credential_file_security(
                    file_path
                )
                audit_results["credential_files"][str(file_path)] = validation

        # Calculate security score
        total_checks = 0
        passed_checks = 0

        for env_data in audit_results["environment_variables"].values():
            total_checks += 1
            if env_data.get("secure", False):
                passed_checks += 1

        for file_data in audit_results["credential_files"].values():
            for check_name, passed in file_data.items():
                total_checks += 1
                if passed:
                    passed_checks += 1

        if total_checks > 0:
            audit_results["security_score"] = round(
                (passed_checks / total_checks) * 100, 1
            )

        # Generate recommendations
        if audit_results["security_score"] < 80:
            audit_results["recommendations"].append(
                "Improve credential security configuration"
            )

        if not audit_results["environment_variables"]:
            audit_results["recommendations"].append(
                "Consider using environment variables for credentials"
            )

        if any(
            Path.cwd() in Path(f).parents for f in audit_results["credential_files"]
        ):
            audit_results["recommendations"].append(
                "Move credential files outside project directory"
            )

        return audit_results


def print_security_guide():
    """Print the complete security guide to console."""
    guide = CredentialSecurityGuide()

    print("🔐 DEP-HALLUCINATOR CREDENTIAL SECURITY GUIDE")
    print("=" * 50)

    print("\n📋 BEST PRACTICES:")
    practices = guide.get_security_best_practices()
    for category, items in practices.items():
        print(f"\n{category}:")
        for item in items:
            print(f"  • {item}")

    print("\n🔧 SETUP INSTRUCTIONS:")
    print(guide.generate_secure_setup_instructions())

    print("\n🔍 SECURITY AUDIT:")
    audit = guide.perform_security_audit()
    print(f"Security Score: {audit['security_score']}%")
    if audit["recommendations"]:
        print("Recommendations:")
        for rec in audit["recommendations"]:
            print(f"  • {rec}")


if __name__ == "__main__":
    print_security_guide()
