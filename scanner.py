#!/usr/bin/env python3
"""WordPress 7.0 compatibility scanner for deprecations and iframe readiness."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


EXTENSIONS = {".php", ".js", ".jsx", ".ts", ".tsx", ".css", ".scss"}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    pattern: str
    message: str
    replacement: str


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule_id: str
    category: str
    severity: str
    message: str
    replacement: str
    snippet: str


RULES = [
    Rule(
        rule_id="WP-DEP-001",
        category="deprecation",
        severity="medium",
        pattern=r"""add_filter\(\s*['"]allowed_block_types['"]""",
        message="Legacy allowed_block_types filter detected.",
        replacement="Use allowed_block_types_all with editor context support.",
    ),
    Rule(
        rule_id="WP-DEP-002",
        category="deprecation",
        severity="medium",
        pattern=r"""add_filter\(\s*['"]block_editor_settings['"]""",
        message="Legacy block_editor_settings filter detected.",
        replacement="Use block_editor_settings_all and inspect WP_Block_Editor_Context.",
    ),
    Rule(
        rule_id="WP-DEP-003",
        category="deprecation",
        severity="low",
        pattern=r"""\bwp\.editor\.initialize\s*\(""",
        message="Classic wp.editor.initialize usage found.",
        replacement="Prefer block APIs in @wordpress/block-editor and @wordpress/data.",
    ),
    Rule(
        rule_id="WP-DEP-004",
        category="deprecation",
        severity="low",
        pattern=r"""\btinyMCEPreInit\b""",
        message="TinyMCE global usage detected.",
        replacement="Migrate editor integrations to block editor APIs where possible.",
    ),
    Rule(
        rule_id="WP-IFRAME-001",
        category="iframe-readiness",
        severity="high",
        pattern=r"""\bwindow\.(?:parent|top)\.document\b|\btop\.document\b""",
        message="Cross-frame DOM access will break when editor runs in isolated iframe.",
        replacement="Use editor data stores/events or postMessage contracts instead of parent/top DOM.",
    ),
    Rule(
        rule_id="WP-IFRAME-002",
        category="iframe-readiness",
        severity="medium",
        pattern=r"""['"](?:#poststuff|#titlediv|#editor)['"]|\.edit-post-layout__content""",
        message="Hardcoded post editor DOM selectors found.",
        replacement="Scope UI to registered block controls or plugin sidebar slots.",
    ),
    Rule(
        rule_id="WP-IFRAME-003",
        category="iframe-readiness",
        severity="medium",
        pattern=r"""add_action\(\s*['"]admin_head-post(?:-new)?\.php['"]""",
        message="Direct post editor head injection detected.",
        replacement="Enqueue assets with block editor hooks and target supported extension points.",
    ),
]


def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in EXTENSIONS:
            yield root
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in EXTENSIONS:
            yield path


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def scan_file(path: Path, base: Path, compiled_rules: list[tuple[Rule, re.Pattern]]) -> list[Finding]:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    lines = content.splitlines()
    rel = str(path.relative_to(base)) if base.is_dir() else str(path)

    for rule, regex in compiled_rules:
        for match in regex.finditer(content):
            ln = line_number(content, match.start())
            snippet = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
            findings.append(
                Finding(
                    file=rel,
                    line=ln,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    message=rule.message,
                    replacement=rule.replacement,
                    snippet=snippet,
                )
            )
    return findings


def scan_path(target: Path) -> list[Finding]:
    compiled_rules = [(rule, re.compile(rule.pattern)) for rule in RULES]
    findings: list[Finding] = []
    for file_path in iter_files(target):
        findings.extend(scan_file(file_path, target, compiled_rules))
    return sorted(findings, key=lambda f: (f.file, f.line, f.rule_id))


def summarize(findings: list[Finding]) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0, "total": len(findings)}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


def render_text(findings: list[Finding], summary: dict[str, int]) -> str:
    lines = [
        "WordPress 7.0 Compatibility Scan",
        f"Findings: {summary['total']} (high={summary['high']}, medium={summary['medium']}, low={summary['low']})",
        "",
    ]
    for finding in findings:
        lines.append(
            f"[{finding.severity.upper()}] {finding.rule_id} {finding.file}:{finding.line} - {finding.message}"
        )
        lines.append(f"  Replacement: {finding.replacement}")
    if not findings:
        lines.append("No compatibility findings detected.")
    return "\n".join(lines)


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    level = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[item.severity] >= level for item in findings)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan WordPress plugin/theme code for deprecations and iframe readiness risks."
    )
    parser.add_argument("path", help="Path to a plugin or theme directory")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low"],
        default="high",
        help="Exit with code 1 when findings at or above this severity are present",
    )
    args = parser.parse_args()

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 2

    findings = scan_path(target)
    summary = summarize(findings)

    if args.format == "json":
        payload = {"path": str(target), "summary": summary, "findings": [asdict(f) for f in findings]}
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(findings, summary))

    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
