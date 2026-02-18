# wp-7-compat-scanner

CLI scanner for WordPress plugin/theme code that flags:
- deprecated WordPress APIs
- deprecated WordPress hooks
- plugin/theme fatal-risk patterns that can crash on modern PHP runtimes

## Why this exists

Before building this tool, I checked maintained options like Plugin Check and other compatibility scanners on WordPress.org. They are useful, but I did not find a maintained WordPress.org tool focused on **both** deprecated hook usage and WP 7.0-forward fatal-risk detection in a simple CI-oriented CLI.

Freshness baseline used for this scanner:
- WordPress stable: `6.9.1` (released February 3, 2026)
- WordPress `7.0` status: still tentative for 2026 (not released yet)

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
| `WP-API-001` | deprecated-api | medium | `get_page_by_title()` | Use `WP_Query` with explicit title constraints |
| `WP-API-002` | deprecated-api | medium | `wp_make_content_images_responsive()` | Use `wp_filter_content_tags()` |
| `WP-DEP-001` | deprecated-hook | medium | `allowed_block_types` filter | Use `allowed_block_types_all` with context |
| `WP-DEP-002` | deprecated-hook | medium | `block_editor_settings` filter | Use `block_editor_settings_all` and context |
| `WP-FATAL-001` | fatal-risk | high | `create_function()` | Replace with closures or named callbacks |
| `WP-FATAL-002` | fatal-risk | high | `mysql_*` APIs | Use `$wpdb`/prepared queries or supported DB APIs |
| `WP-FATAL-003` | fatal-risk | high | `each()` | Replace with `foreach` |
| `WP-FATAL-004` | fatal-risk | high | `call_user_method*()` | Replace with `call_user_func()` or direct method call |

## Testing

```bash
python3 -m compileall scanner.py tests
python3 -m unittest discover -s tests -v
```
