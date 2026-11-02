"""
NightCrawler - Testing Permission Manager Module
Enforces granular authorization policies across reconnaissance modules.
Guarantees fail-closed safety: destructive actions and DoS are permanently prohibited.
"""

from typing import Dict, Any, Optional
from src.core.program_profile import TestingPermissionsDefinition, ProgramProfile


class TestingPermissionManager:
    """
    Evaluates whether a reconnaissance or security testing activity is permitted
    under the active program policy and global safety ceilings.
    """
    __test__ = False  # Prevent pytest from treating this as a test class

    # Actions that are permanently disabled across ALL programs and configurations
    GLOBAL_PROHIBITED_ACTIONS = {
        "destructive_testing",
        "denial_of_service"
    }

    def __init__(self, permissions: Optional[TestingPermissionsDefinition] = None, allow_credential_validation: bool = False):
        self.permissions = permissions or TestingPermissionsDefinition()
        # Credential validation requires BOTH profile permission AND explicit operator override
        self._operator_allowed_cred_validation = allow_credential_validation

    @classmethod
    def from_profile(cls, profile: ProgramProfile, allow_credential_validation: bool = False) -> "TestingPermissionManager":
        return cls(permissions=profile.testing_permissions, allow_credential_validation=allow_credential_validation)

    def is_permitted(self, action_name: str) -> bool:
        """
        Check if a given action is allowed.
        Fails closed (returns False) for unknown or prohibited actions.
        """
        action = action_name.lower().strip()

        # 1. Global hard safety limits
        if action in self.GLOBAL_PROHIBITED_ACTIONS:
            return False

        # 2. Credential validation safety gate
        if action == "credential_validation":
            return bool(self.permissions.credential_validation and self._operator_allowed_cred_validation)

        # 3. Standard testing categories
        if hasattr(self.permissions, action):
            return bool(getattr(self.permissions, action))

        return False

    def assert_permitted(self, action_name: str):
        """Raise PermissionError if action is not authorized by policy."""
        if not self.is_permitted(action_name):
            raise PermissionError(
                f"Action '{action_name}' is PROHIBITED under the active program policy or global safety rules."
            )

    def get_effective_permissions(self) -> Dict[str, bool]:
        """Return full map of effective permissions."""
        all_actions = [
            "passive_recon",
            "active_recon",
            "endpoint_discovery",
            "javascript_analysis",
            "secret_detection",
            "credential_validation",
            "fuzzing",
            "injection_testing",
            "destructive_testing",
            "denial_of_service",
            "social_engineering"
        ]
        return {action: self.is_permitted(action) for action in all_actions}
