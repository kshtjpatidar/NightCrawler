"""
NightCrawler - Program Manager Module
Handles lifecycle management, discovery, and manipulation of bug bounty program profiles.
"""

import os
import shutil
import json
import errno
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import yaml

from src.core.program_profile import ProgramProfile, PolicyParser, PolicyValidator


def safe_lexists(path: Union[str, Path]) -> bool:
    """
    Check if a filesystem entry exists (including broken symlinks) without masking
    PermissionError or unexpected filesystem OSError conditions.

    Returns True if the path exists (or is a symlink, regardless of target existence).
    Returns False ONLY if FileNotFoundError or ENOTDIR occurs (demonstrably absent).
    Propagates PermissionError (EACCES/EPERM) and all unexpected filesystem OSError conditions.
    """
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError as err:
        if err.errno in (errno.ENOENT, errno.ENOTDIR):
            return False
        raise


class ProgramManager:
    """Manages program profiles in the programs/ repository directory."""

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            # Root directory of NightCrawler project
            self.base_dir = Path(__file__).parent.parent.parent / "programs"

    def list_profiles(self) -> List[Dict[str, Any]]:
        """Return summary of all available program profiles."""
        if not safe_lexists(self.base_dir):
            return []
        if not self.base_dir.is_dir():
            raise ValueError(f"Program profile repository path '{self.base_dir}' is not a directory.")
        profiles = []
        for p_dir in self.base_dir.iterdir():
            if p_dir.is_dir():
                yaml_file = p_dir / "program.yaml"
                json_file = p_dir / "program.json"
                has_y = safe_lexists(yaml_file)
                has_j = safe_lexists(json_file)
                if has_y and has_j:
                    profiles.append({
                        "id": p_dir.name,
                        "name": p_dir.name,
                        "platform": "Unknown",
                        "max_rps": "N/A",
                        "allowed_domains": 0,
                        "valid": False,
                        "errors": ["Ambiguous profile configuration: both 'program.yaml' and 'program.json' exist."],
                        "requires_review": False,
                        "path": str(p_dir)
                    })
                    continue
                target_file = yaml_file if has_y else (json_file if has_j else None)
                if target_file:
                    try:
                        if target_file.is_dir() or (target_file.is_symlink() and not target_file.resolve().is_file()):
                            raise ValueError(f"Profile file '{target_file}' is an unexpected filesystem object (not a regular file).")
                        if target_file.suffix == ".yaml":
                            profile = PolicyParser.from_yaml_file(target_file)
                        else:
                            profile = PolicyParser.from_json_file(target_file)
                        errors = PolicyValidator.validate(profile)
                        profiles.append({
                            "id": profile.id,
                            "name": profile.name,
                            "platform": profile.platform,
                            "max_rps": profile.request_policy.max_rps,
                            "allowed_domains": len(profile.scope.allowed_domains),
                            "valid": len(errors) == 0,
                            "errors": errors,
                            "requires_review": profile.requires_review,
                            "path": str(target_file)
                        })
                    except Exception as e:
                        profiles.append({
                            "id": p_dir.name,
                            "name": p_dir.name,
                            "platform": "Unknown",
                            "max_rps": "N/A",
                            "allowed_domains": 0,
                            "valid": False,
                            "errors": [f"Failed to parse profile: {e}"],
                            "requires_review": False,
                            "path": str(target_file or p_dir)
                        })
                else:
                    profiles.append({
                        "id": p_dir.name,
                        "name": p_dir.name,
                        "platform": "Unknown",
                        "max_rps": "N/A",
                        "allowed_domains": 0,
                        "valid": False,
                        "errors": ["Profile directory exists but contains no recognized profile file ('program.yaml' or 'program.json')."],
                        "requires_review": False,
                        "path": str(p_dir)
                    })
        return sorted(profiles, key=lambda x: x["id"])

    def find_profile_path(self, program_id: str) -> Optional[Path]:
        """
        Locate the profile directory or filesystem entry for program_id in base_dir.
        Uses case-insensitive matching and os.lstat to detect symlinks and unusual objects
        without masking PermissionError or unexpected filesystem OSError conditions.

        Missing-directory fallback rule:
        If self.base_dir is demonstrably absent (does not exist on the filesystem),
        no profile can be present. Returns None, permitting fallback to base configuration.
        An inaccessible directory (PermissionError or I/O error) is NOT treated as absent.

        Failure modes:
        - If self.base_dir is inaccessible (PermissionError or filesystem OSError), propagates error.
        - If self.base_dir exists but is not a directory, raises ValueError.
        - If iteration over self.base_dir encounters PermissionError or filesystem OSError, propagates error.
        - If the profile is demonstrably absent after successful iteration, returns None.
        - If a matching entry is found, returns the Path to that entry.
        """
        # 1. Distinguish demonstrably missing base_dir from inaccessible base_dir
        if not safe_lexists(self.base_dir):
            return None

        # Ensure base_dir is actually a directory (or valid symlink to directory)
        if not self.base_dir.is_dir():
            raise ValueError(f"Program profile repository path '{self.base_dir}' is an unexpected filesystem object (expected a directory).")

        clean_id = program_id.strip().lower()
        direct = self.base_dir / clean_id
        if safe_lexists(direct):
            return direct

        # 2. Case-insensitive search across directory entries.
        # Do NOT catch PermissionError or unexpected OSError - propagate them!
        for sub in self.base_dir.iterdir():
            if sub.name.lower() == clean_id and safe_lexists(sub):
                return sub

        return None

    def profile_exists(self, program_id: str) -> bool:
        """
        Check if a program profile directory or filesystem entry exists on disk.
        Returns False ONLY when the profile is genuinely absent according to documented rule:
        no directory, file, symlink, or filesystem entry matching program_id exists in base_dir.
        Returns True if any matching filesystem entry exists.
        Propagates PermissionError and unexpected filesystem OSError conditions.
        """
        return self.find_profile_path(program_id) is not None

    def get_profile(self, program_id: str) -> Optional[ProgramProfile]:
        """
        Load and return a program profile by ID or directory name.

        Failure modes:
        - If genuinely absent according to documented rule, returns None.
        - If the profile path is an unexpected filesystem object (not a directory, broken symlink), raises ValueError.
        - If the profile directory exists but has no recognized profile file (empty or unexpected files), raises ValueError.
        - If both 'program.yaml' and 'program.json' exist, raises ValueError (ambiguous configuration).
        - If the profile file is not a regular file or is a broken symlink, raises ValueError.
        - If the profile file is unreadable (PermissionError), raises PermissionError.
        - If the profile file is malformed YAML/JSON, raises parsing exception.
        - If the profile file contains invalid policy fields, raises PolicyValidationError.
        """
        target_path = self.find_profile_path(program_id)
        if target_path is None:
            return None

        # 1. Inspect target_path itself
        if target_path.is_symlink():
            try:
                resolved_dir = target_path.resolve(strict=True)
            except FileNotFoundError:
                raise ValueError(
                    f"Program profile path '{target_path}' is a broken symlink pointing to a non-existent target."
                )
            except OSError as err:
                if err.errno in (errno.ENOENT, errno.ENOTDIR):
                    raise ValueError(
                        f"Program profile path '{target_path}' is a broken symlink pointing to a non-existent target."
                    )
                raise
            if not resolved_dir.is_dir():
                raise ValueError(
                    f"Program profile path '{target_path}' resolves to an unexpected filesystem object (not a directory): {resolved_dir}"
                )
        elif not target_path.is_dir():
            raise ValueError(
                f"Program profile path '{target_path}' is an unexpected filesystem object (expected a directory, got {type(target_path).__name__})."
            )
        else:
            resolved_dir = target_path

        # 2. Inspect profile files within the directory
        yaml_file = resolved_dir / "program.yaml"
        json_file = resolved_dir / "program.json"

        has_yaml = safe_lexists(yaml_file)
        has_json = safe_lexists(json_file)

        if has_yaml and has_json:
            raise ValueError(
                f"Ambiguous profile configuration in '{resolved_dir}': both 'program.yaml' and 'program.json' exist. "
                f"Exactly one profile configuration file must be present."
            )

        if not has_yaml and not has_json:
            raise ValueError(
                f"Program profile directory '{resolved_dir}' exists but contains no recognized profile file "
                f"('program.yaml' or 'program.json')."
            )

        target_file = yaml_file if has_yaml else json_file

        # 3. Inspect target_file itself
        if target_file.is_symlink():
            try:
                resolved_file = target_file.resolve(strict=True)
            except FileNotFoundError:
                raise ValueError(f"Profile file '{target_file}' is a broken symlink.")
            except OSError as err:
                if err.errno in (errno.ENOENT, errno.ENOTDIR):
                    raise ValueError(f"Profile file '{target_file}' is a broken symlink.")
                raise
            if not resolved_file.is_file():
                raise ValueError(
                    f"Profile file '{target_file}' resolves to an unexpected filesystem object (expected regular file): {resolved_file}"
                )
        elif not target_file.is_file():
            raise ValueError(
                f"Profile file '{target_file}' is an unexpected filesystem object (expected regular file)."
            )

        # 4. Load and parse (preserving unreadable / malformed / policy errors)
        if target_file.suffix == ".yaml":
            return PolicyParser.from_yaml_file(target_file)
        else:
            return PolicyParser.from_json_file(target_file)

    def validate_profile(self, program_id: str) -> List[str]:
        """Validate a profile by ID."""
        profile = self.get_profile(program_id)
        if not profile:
            return [f"Program profile '{program_id}' not found."]
        return PolicyValidator.validate(profile)

    def create_profile(self, profile_data: Dict[str, Any], save: bool = True) -> ProgramProfile:
        """Create a new program profile and optionally save to disk."""
        profile = PolicyParser.from_dict(profile_data)
        errors = PolicyValidator.validate(profile)
        if errors:
            raise ValueError(f"Invalid profile configuration: {', '.join(errors)}")

        if save:
            target_path = self.base_dir / profile.id / "program.yaml"
            profile.save_yaml(target_path)
        return profile

    def update_profile(self, program_id: str, updates: Dict[str, Any]) -> ProgramProfile:
        """Update an existing program profile."""
        current = self.get_profile(program_id)
        if not current:
            raise ValueError(f"Program profile '{program_id}' not found.")

        current_dict = current.to_dict()

        # Deep merge updates
        def deep_update(base: dict, u: dict):
            for k, v in u.items():
                if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                    deep_update(base[k], v)
                else:
                    base[k] = v

        deep_update(current_dict, updates)
        updated_profile = PolicyParser.from_dict(current_dict)
        errors = PolicyValidator.validate(updated_profile)
        if errors:
            raise ValueError(f"Validation failed after update: {', '.join(errors)}")

        target_path = self.base_dir / updated_profile.id / "program.yaml"
        updated_profile.save_yaml(target_path)
        return updated_profile

    def import_profile(self, source_path_or_str: str, format_hint: str = "auto") -> ProgramProfile:
        """Import a profile from a file path or serialized string (YAML/JSON/text)."""
        p = Path(source_path_or_str)
        if p.exists() and p.is_file():
            content = p.read_text(encoding="utf-8")
            ext = p.suffix.lower()
            if ext in (".yaml", ".yml"):
                data = yaml.safe_load(content)
                profile = PolicyParser.from_dict(data, source_ref=str(p))
            elif ext == ".json":
                data = json.loads(content)
                profile = PolicyParser.from_dict(data, source_ref=str(p))
            else:
                profile = PolicyParser.from_text_rules(p.stem, p.stem.title(), content)
        else:
            # String input
            content = source_path_or_str.strip()
            if content.startswith("{"):
                data = json.loads(content)
                profile = PolicyParser.from_dict(data, source_ref="string_json")
            elif "\n" in content and ":" in content:
                try:
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        profile = PolicyParser.from_dict(data, source_ref="string_yaml")
                    else:
                        profile = PolicyParser.from_text_rules("imported-program", "Imported Program", content)
                except Exception:
                    profile = PolicyParser.from_text_rules("imported-program", "Imported Program", content)
            else:
                profile = PolicyParser.from_text_rules("imported-program", "Imported Program", content)

        # Save imported profile
        target_path = self.base_dir / profile.id / "program.yaml"
        profile.save_yaml(target_path)
        return profile

    def export_profile(self, program_id: str, output_path: str, export_format: str = "yaml") -> Path:
        """Export a profile to the specified output file in YAML or JSON."""
        profile = self.get_profile(program_id)
        if not profile:
            raise ValueError(f"Program profile '{program_id}' not found.")

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        data = profile.to_dict()

        if export_format.lower() == "json" or out.suffix.lower() == ".json":
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            with open(out, "w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        return out

    def duplicate_profile(self, source_id: str, new_id: str, new_name: Optional[str] = None) -> ProgramProfile:
        """Duplicate an existing profile under a new ID and name."""
        source = self.get_profile(source_id)
        if not source:
            raise ValueError(f"Source program profile '{source_id}' not found.")

        data = source.to_dict()
        data["id"] = new_id.lower().strip()
        data["name"] = new_name or f"{source.name} (Copy)"
        new_profile = PolicyParser.from_dict(data)

        target_path = self.base_dir / new_profile.id / "program.yaml"
        new_profile.save_yaml(target_path)
        return new_profile
