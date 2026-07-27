from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import uuid
from typing import Any, Dict, Mapping, Optional

from agent_roi._serialization import to_jsonable


_DEFAULT_ARTIFACT_FILES = {
    "audit.jsonl",
    "audit.sqlite3",
    "executive_brief.md",
    "manifest.json",
    "recommendations.csv",
    "roi_report.md",
}


def create_artifact_dir(
    demo_name: str,
    outdir: str | Path | None = None,
    *,
    allow_existing: bool = False,
    clean_known_artifacts: bool = False,
) -> Path:
    """Create an artifact directory without silently mixing separate runs.

    An explicit non-empty directory is rejected by default. Set
    ``clean_known_artifacts=True`` only when the caller intentionally wants to
    replace files produced by an earlier Agent-ROI run.
    """
    if not isinstance(demo_name, str) or not demo_name.strip():
        raise ValueError("demo_name must be a non-empty string")

    if outdir is not None:
        path = Path(outdir)
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        run_suffix = uuid.uuid4().hex[:12]
        path = Path("artifacts") / demo_name.strip() / f"{timestamp}_{run_suffix}"

    if path.is_symlink():
        raise ValueError(f"Artifact directory must not be a symbolic link: {path}")

    if path.exists() and any(path.iterdir()):
        if clean_known_artifacts:
            unknown = {item.name for item in path.iterdir()} - _DEFAULT_ARTIFACT_FILES
            if unknown:
                raise FileExistsError(
                    f"Refusing to clean {path}; it contains non-Agent-ROI files: {sorted(unknown)}"
                )
            for item in path.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
        elif not allow_existing:
            raise FileExistsError(
                f"Artifact directory is not empty: {path}. Use a new directory or explicit overwrite."
            )

    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def atomic_write_text(path: str | Path, content: str, *, encoding: str = "utf-8") -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(content, encoding=encoding)
        temporary.replace(target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def write_manifest(
    artifact_dir: str | Path,
    *,
    demo_name: str,
    business_context: Mapping[str, Any],
    decision_outcome: str,
    confidence: float,
    extra: Optional[Dict[str, Any]] = None,
) -> Path:
    directory = Path(artifact_dir)
    directory.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {
        "demo": demo_name,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "business_context": dict(business_context),
        "decision_outcome": decision_outcome,
        "confidence": round(float(confidence), 4),
    }
    if extra:
        manifest.update(extra)
    safe = to_jsonable(manifest)
    return atomic_write_text(
        directory / "manifest.json",
        json.dumps(safe, indent=2, sort_keys=True, ensure_ascii=False),
    )
