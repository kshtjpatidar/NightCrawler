"""
NightCrawler - Program Manager Module
Handles lifecycle management, discovery, and manipulation of bug bounty program profiles.
"""

import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml

from src.core.program_profile import ProgramProfile, PolicyParser, PolicyValidator


class ProgramManager:
    """Manages program profiles in the programs/ repository directory."""

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            # Root directory of NightCrawler project
            self.base_dir = Path(__file__).parent.parent.parent / "programs"
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def list_profiles(self) -> List[Dict[str, Any]]:
        """Return summary of all available program profiles."""
        profiles = []
        for p_dir in self.base_dir.iterdir():
            if p_dir.is_dir():
                yaml_file = p_dir / "program.yaml"
                json_file = p_dir / "program.json"
                target_file = yaml_file if yaml_file.exists() else (json_file if json_file.exists() else None)
                if target_file:
                    try:
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
        return sorted(profiles, key=lambda x: x["id"])

    def profile_exists(self, program_id: str) -> bool:
        """Check if a program profile file or directory exists on disk."""
        clean_id = program_id.strip().lower()
        prog_dir = self.base_dir / clean_id
        if prog_dir.exists():
            if (prog_dir / "program.yaml").exists() or (prog_dir / "program.json").exists():
                return True
        for sub in self.base_dir.iterdir():
            if sub.is_dir() and sub.name.lower() == clean_id:
                if (sub / "program.yaml").exists() or (sub / "program.json").exists():
                    return True
        return False

    def get_profile(self, program_id: str) -> Optional[ProgramProfile]:
        """Load and return a program profile by ID or directory name."""
        clean_id = program_id.strip().lower()
        prog_dir = self.base_dir / clean_id
        target_file = None

        if prog_dir.exists():
            y_file = prog_dir / "program.yaml"
            j_file = prog_dir / "program.json"
            if y_file.exists():
                target_file = y_file
            elif j_file.exists():
                target_file = j_file

        if target_file is None:
            # Try searching by id match across all profiles
            for sub in self.base_dir.iterdir():
                if sub.is_dir():
                    y_file = sub / "program.yaml"
                    j_file = sub / "program.json"
                    f = y_file if y_file.exists() else (j_file if j_file.exists() else None)
                    if f and sub.name.lower() == clean_id:
                        target_file = f
                        break

        if target_file is None:
            return None

        # Do not swallow exceptions: malformed YAML, PermissionError, PolicyValidationError raise directly
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
