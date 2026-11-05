"""
NightCrawler - Program Manager Module
Handles lifecycle management, discovery, and manipulation of bug bounty program profiles.
"""

import os
import re
import shutil
import json
import errno
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import yaml

from src.core.program_profile import ProgramProfile, PolicyParser, PolicyValidator

PROGRAM_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')


def validate_program_id(program_id: Any) -> str:
    r"""
    Centralized program ID validation.
    Enforces strict identifier syntax: non-empty string matching ^[a-zA-Z0-9_-]+$.
    Explicitly rejects traversal characters (.., /, \), drive prefixes (C:),
    null bytes, Unicode or encoded variants, absolute paths, and whitespace.
    Returns the validated, lowercased program ID string.
    """
    if not isinstance(program_id, str):
        raise ValueError(f"Program profile ID must be a string, got {type(program_id).__name__}.")
    raw = program_id.strip()
    if not raw:
        raise ValueError("Program profile ID cannot be empty or whitespace-only.")
    if "\x00" in program_id or "/" in program_id or "\\" in program_id or ".." in program_id or ":" in program_id:
        raise ValueError(f"Invalid program profile ID containing traversal sequences or path separators: '{program_id}'")
    if not PROGRAM_ID_PATTERN.match(raw):
        raise ValueError(
            f"Invalid program profile ID: '{program_id}'. "
            "Program IDs must contain only alphanumeric characters, hyphens, and underscores."
        )
    return raw.lower()


def safe_lexists(path: Union[str, Path]) -> bool:
    """
    Check if a filesystem entry exists (including broken symlinks) without masking
    NotADirectoryError (ENOTDIR), PermissionError (EACCES/EPERM), or unexpected
    filesystem OSError conditions.

    Returns True if the path exists (or is a symlink, regardless of target existence).
    Returns False ONLY if FileNotFoundError or errno.ENOENT occurs (demonstrably absent).
    Propagates NotADirectoryError (ENOTDIR), PermissionError (EACCES/EPERM), EIO,
    and all unexpected filesystem OSError conditions.
    """
    try:
        os.lstat(path)
        return True
    except NotADirectoryError:
        raise
    except FileNotFoundError:
        return False
    except OSError as err:
        if err.errno == errno.ENOENT:
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

    def _get_canonical_base(self, create: bool = False) -> Path:
        """
        Resolve the canonical base repository root without swallowing
        PermissionError, ENOTDIR, or unexpected filesystem errors.
        """
        if create and not safe_lexists(self.base_dir):
            self.base_dir.mkdir(parents=True, exist_ok=True)

        if not safe_lexists(self.base_dir):
            raise FileNotFoundError(f"Program profile repository path '{self.base_dir}' does not exist.")
        if not self.base_dir.is_dir():
            raise ValueError(f"Program profile repository path '{self.base_dir}' is an unexpected filesystem object (expected a directory).")
        try:
            return self.base_dir.resolve(strict=True)
        except (NotADirectoryError, PermissionError):
            raise
        except OSError as err:
            if err.errno == errno.ENOENT:
                raise FileNotFoundError(f"Program profile repository path '{self.base_dir}' does not exist.")
            raise

    def _assert_contained(
        self,
        candidate_path: Union[str, Path],
        canonical_base: Optional[Path] = None,
        item_name: str = "path",
        allow_missing: bool = False
    ) -> Path:
        """
        Verify that candidate_path resolves strictly within canonical_base.
        Rejects:
        - Escaping symlinks (candidate resolves outside canonical_base)
        - Paths resolving to canonical_base itself (cannot be the root directory)
        - Broken symlinks if allow_missing is False
        - Unexpected filesystem errors are propagated, not swallowed.
        Returns the resolved canonical Path.
        """
        base = canonical_base or self._get_canonical_base()
        p = Path(candidate_path)

        if p.is_symlink():
            try:
                resolved = p.resolve(strict=True)
            except (FileNotFoundError, OSError) as err:
                if isinstance(err, (NotADirectoryError, PermissionError)):
                    raise
                if getattr(err, "errno", None) in (errno.ENOTDIR, errno.EACCES, errno.EPERM):
                    raise
                # Broken symlink
                raise ValueError(f"Program profile {item_name} '{p}' is a broken symlink pointing to a non-existent target.")
            try:
                resolved.relative_to(base)
            except ValueError:
                raise ValueError(f"Symlink escape detected: {item_name} '{p}' resolves to '{resolved}', which is outside profile repository '{base}'.")
            if resolved == base:
                raise ValueError(f"Invalid {item_name} '{p}': resolves to repository root itself.")
            return resolved

        # Non-symlink path
        try:
            resolved = p.resolve(strict=True)
        except (FileNotFoundError, OSError) as err:
            if isinstance(err, (NotADirectoryError, PermissionError)):
                raise
            if getattr(err, "errno", None) in (errno.ENOTDIR, errno.EACCES, errno.EPERM):
                raise
            if allow_missing and (isinstance(err, FileNotFoundError) or getattr(err, "errno", None) == errno.ENOENT):
                parent_resolved = p.parent.resolve(strict=True)
                try:
                    parent_resolved.relative_to(base)
                except ValueError:
                    raise ValueError(f"Path escape detected: parent directory of {item_name} '{p}' resolves outside repository root '{base}'.")
                return parent_resolved / p.name
            raise

        try:
            resolved.relative_to(base)
        except ValueError:
            raise ValueError(f"Path escape detected: {item_name} '{p}' resolves outside profile repository '{base}'.")
        if resolved == base:
            raise ValueError(f"Invalid {item_name} '{p}': resolves to repository root itself.")
        return resolved

    def _safe_write_yaml(self, profile: ProgramProfile, target_path: Path, canonical_base: Path):
        """
        Safely write profile YAML avoiding symlink following and race conditions.
        Enforces canonical containment of parent directory and uses O_NOFOLLOW.
        """
        self._assert_contained(target_path.parent, canonical_base, item_name="target directory")
        if target_path.is_symlink():
            raise ValueError(f"Cannot write profile: destination path '{target_path}' is a symlink.")

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(target_path, flags, 0o644)
        except OSError as err:
            if err.errno == errno.ELOOP or getattr(err, "errno", None) == getattr(errno, "EMLINK", None):
                raise ValueError(f"Symlink escape detected: '{target_path}' is a symlink.")
            raise

        data = profile.to_dict()
        yaml_bytes = yaml.dump(data, default_flow_style=False, sort_keys=False).encode("utf-8")
        with os.fdopen(fd, "wb") as f:
            f.write(yaml_bytes)

    def list_profiles(self) -> List[Dict[str, Any]]:
        """Return summary of all available program profiles."""
        if not safe_lexists(self.base_dir):
            return []
        if not self.base_dir.is_dir():
            raise ValueError(f"Program profile repository path '{self.base_dir}' is not a directory.")
        profiles = []
        canonical_base = self._get_canonical_base()
        for p_dir in self.base_dir.iterdir():
            if p_dir.is_dir():
                try:
                    resolved_dir = self._assert_contained(p_dir, canonical_base, item_name=f"profile directory '{p_dir}'")
                except ValueError as err:
                    profiles.append({
                        "id": p_dir.name,
                        "name": p_dir.name,
                        "platform": "Unknown",
                        "max_rps": "N/A",
                        "allowed_domains": 0,
                        "valid": False,
                        "errors": [str(err)],
                        "requires_review": False,
                        "path": str(p_dir)
                    })
                    continue

                yaml_file = resolved_dir / "program.yaml"
                json_file = resolved_dir / "program.json"
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
                        resolved_file = self._assert_contained(target_file, canonical_base, item_name=f"profile file '{target_file}'")
                        if not resolved_file.is_file():
                            raise ValueError(f"Profile file '{target_file}' is an unexpected filesystem object (not a regular file).")
                        if resolved_file.suffix == ".yaml":
                            profile = PolicyParser.from_yaml_file(resolved_file)
                        else:
                            profile = PolicyParser.from_json_file(resolved_file)
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
                        if isinstance(e, (PermissionError, NotADirectoryError)):
                            raise
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
        Enforces canonical containment: rejecting any symlink that escapes base_dir.
        """
        clean_id = validate_program_id(program_id)

        # 1. Distinguish demonstrably missing base_dir from inaccessible base_dir
        if not safe_lexists(self.base_dir):
            return None

        canonical_base = self._get_canonical_base()
        direct = self.base_dir / clean_id
        if safe_lexists(direct):
            self._assert_contained(direct, canonical_base, item_name=f"profile directory '{direct}'")
            return direct

        # 2. Case-insensitive search across directory entries.
        # Do NOT catch PermissionError or unexpected OSError - propagate them!
        for sub in self.base_dir.iterdir():
            if sub.name.lower() == clean_id and safe_lexists(sub):
                self._assert_contained(sub, canonical_base, item_name=f"profile directory '{sub}'")
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
        - If the profile path or its files are symlinks escaping the repository, raises ValueError.
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

        canonical_base = self._get_canonical_base()

        # 1. Inspect target_path itself and assert containment
        resolved_dir = self._assert_contained(target_path, canonical_base, item_name=f"profile directory '{target_path}'")
        if not resolved_dir.is_dir():
            raise ValueError(
                f"Program profile path '{target_path}' resolves to an unexpected filesystem object (expected a directory, got {type(target_path).__name__})."
            )

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

        # 3. Inspect target_file itself and assert containment
        resolved_file = self._assert_contained(target_file, canonical_base, item_name=f"profile file '{target_file}'")
        if not resolved_file.is_file():
            raise ValueError(
                f"Profile file '{target_file}' resolves to an unexpected filesystem object (expected regular file): {resolved_file}"
            )

        # 4. Load and parse (preserving unreadable / malformed / policy errors)
        if resolved_file.suffix == ".yaml":
            return PolicyParser.from_yaml_file(resolved_file)
        else:
            return PolicyParser.from_json_file(resolved_file)

    def validate_profile(self, program_id: str) -> List[str]:
        """Validate a profile by ID."""
        clean_id = validate_program_id(program_id)
        profile = self.get_profile(clean_id)
        if not profile:
            return [f"Program profile '{program_id}' not found."]
        return PolicyValidator.validate(profile)

    def create_profile(self, profile_data: Dict[str, Any], save: bool = True) -> ProgramProfile:
        """Create a new program profile and optionally save to disk."""
        profile = PolicyParser.from_dict(profile_data)
        clean_id = validate_program_id(profile.id)
        profile.id = clean_id
        errors = PolicyValidator.validate(profile)
        if errors:
            raise ValueError(f"Invalid profile configuration: {', '.join(errors)}")

        if save:
            canonical_base = self._get_canonical_base(create=True)
            target_dir = self.base_dir / clean_id

            if target_dir.is_symlink():
                raise ValueError(f"Cannot create profile: target directory '{clean_id}' is a symlink.")
            if safe_lexists(target_dir):
                raise ValueError(f"Cannot create profile: profile '{clean_id}' already exists in repository.")

            self._assert_contained(target_dir, canonical_base, item_name=f"target directory '{clean_id}'", allow_missing=True)

            target_dir.mkdir(parents=True, exist_ok=False)
            target_path = target_dir / "program.yaml"
            self._safe_write_yaml(profile, target_path, canonical_base)
        return profile

    def update_profile(self, program_id: str, updates: Dict[str, Any]) -> ProgramProfile:
        """Update an existing program profile."""
        clean_id = validate_program_id(program_id)
        current = self.get_profile(clean_id)
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
        updated_clean_id = validate_program_id(updated_profile.id)
        updated_profile.id = updated_clean_id

        errors = PolicyValidator.validate(updated_profile)
        if errors:
            raise ValueError(f"Validation failed after update: {', '.join(errors)}")

        canonical_base = self._get_canonical_base()
        target_dir = self.base_dir / updated_clean_id

        if target_dir.is_symlink():
            raise ValueError(f"Cannot update profile: profile directory '{target_dir}' is a symlink.")
        if not safe_lexists(target_dir) or not target_dir.is_dir():
            raise ValueError(f"Cannot update profile: target directory '{target_dir}' does not exist or is not a directory.")

        self._assert_contained(target_dir, canonical_base, item_name=f"target directory '{target_dir}'")

        target_path = target_dir / "program.yaml"
        if target_path.is_symlink():
            raise ValueError(f"Cannot update profile: target file '{target_path}' is a symlink.")

        self._safe_write_yaml(updated_profile, target_path, canonical_base)
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

        clean_id = validate_program_id(profile.id)
        profile.id = clean_id

        errors = PolicyValidator.validate(profile)
        if errors:
            raise ValueError(f"Invalid profile configuration in import: {', '.join(errors)}")

        canonical_base = self._get_canonical_base(create=True)
        target_dir = self.base_dir / clean_id

        if target_dir.is_symlink():
            raise ValueError(f"Cannot import profile: target directory '{clean_id}' is a symlink.")
        if safe_lexists(target_dir):
            raise ValueError(f"Cannot import profile: profile '{clean_id}' already exists in repository.")

        self._assert_contained(target_dir, canonical_base, item_name=f"target directory '{clean_id}'", allow_missing=True)

        target_dir.mkdir(parents=True, exist_ok=False)
        target_path = target_dir / "program.yaml"
        self._safe_write_yaml(profile, target_path, canonical_base)
        return profile

    def export_profile(self, program_id: str, output_path: str, export_format: str = "yaml") -> Path:
        """Export a profile to the specified output file in YAML or JSON."""
        clean_id = validate_program_id(program_id)
        profile = self.get_profile(clean_id)
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
        clean_new_id = validate_program_id(new_id)
        clean_source_id = validate_program_id(source_id)
        source = self.get_profile(clean_source_id)
        if not source:
            raise ValueError(f"Source program profile '{source_id}' not found.")

        canonical_base = self._get_canonical_base(create=True)
        target_dir = self.base_dir / clean_new_id

        if target_dir.is_symlink():
            raise ValueError(f"Cannot duplicate profile: target directory '{clean_new_id}' is a symlink.")
        if safe_lexists(target_dir):
            raise ValueError(f"Cannot duplicate profile: target profile directory '{clean_new_id}' already exists.")

        self._assert_contained(target_dir, canonical_base, item_name=f"target directory '{clean_new_id}'", allow_missing=True)

        data = source.to_dict()
        data["id"] = clean_new_id
        data["name"] = new_name or f"{source.name} (Copy)"
        new_profile = PolicyParser.from_dict(data)

        errors = PolicyValidator.validate(new_profile)
        if errors:
            raise ValueError(f"Validation failed for duplicated profile: {', '.join(errors)}")

        target_dir.mkdir(parents=True, exist_ok=False)
        target_path = target_dir / "program.yaml"
        self._safe_write_yaml(new_profile, target_path, canonical_base)
        return new_profile
