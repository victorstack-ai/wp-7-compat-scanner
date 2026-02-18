# wp-7-compat-scanner

CLI scanner for WordPress plugin/theme code that flags:
- WordPress editor API/filter deprecations
- iframe editor readiness risks for WordPress 7.0 era block editor workflows

## Why this exists

Before building this tool, I checked for a maintained plugin focused on **both** static deprecation scanning and iframe editor readiness checks. I did not find a maintained WordPress.org plugin that provides this combined CI-friendly CLI behavior, so this project implements custom logic for that gap.

Freshness baseline used for this scanner:
- WordPress stable: `6.9.1` (released February 3, 2026)
- WordPress `7.0` target date: April 9, 2026

## Usage

```bash
python3 scanner.py /path/to/plugin-or-theme
python3 scanner.py /path/to/plugin-or-theme --format json --fail-on medium
```

Exit codes:
- `0`: no findings at selected threshold
- `1`: findings detected at or above threshold
- `2`: invalid input path

## Current checks

| Rule ID | Category | Severity | Detects | Migration guidance |
|---|---|---|---|---|
| `WP-DEP-001` | deprecation | medium | `allowed_block_types` filter | Use `allowed_block_types_all` with context |
| `WP-DEP-002` | deprecation | medium | `block_editor_settings` filter | Use `block_editor_settings_all` |
| `WP-DEP-003` | deprecation | low | `wp.editor.initialize()` | Move to block editor packages/data stores |
| `WP-DEP-004` | deprecation | low | `tinyMCEPreInit` global usage | Prefer block editor extension APIs |
| `WP-IFRAME-001` | iframe-readiness | high | `window.parent/top.document` access | Use data store/events or `postMessage` contracts |
| `WP-IFRAME-002` | iframe-readiness | medium | Hardcoded editor DOM selectors | Use block slots/sidebar APIs |
| `WP-IFRAME-003` | iframe-readiness | medium | `admin_head-post.php` injections | Use block editor enqueue hooks |

## Testing

```bash
python3 -m unittest discover -s tests -v
```
