# DP Security Standards

Shared security checks for all WordPress code by DP: custom `dp-*` plugins, ACF and native Gutenberg blocks,
Bricks child themes, mu-plugins and WPCodeBox snippets.

- **Why** a rule exists lives in the living doc
  [WordPress Security Watch](https://claude.ai/artifact/E7Wob6EV5ZBZnmKYAsWw8b) (classes, case studies, weekly digest).
- **This repo enforces it:** a PHPCS ruleset with security sniffs only, Semgrep rules `DP-SEC-NNN`, a bad and a
  good fixture for every rule, and a reusable GitHub workflow that every plugin/theme repo calls.

The gate is security-first: CI fails only on security **errors**. Formatting sniffs are deliberately absent.
Existing findings go into a baseline, so the gate fails on new problems, not on history.

## Rule catalog

Severity: **error** fails the gate (unless baselined), **warning** is reported only.

| ID | What it catches | Implemented by | Severity |
| --- | --- | --- | --- |
| DP-SEC-001 | REST route that writes, with `permission_callback` open (`__return_true`, `fn() => true`, `''`, `null`) or missing | Semgrep `dp-sec-001` | error |
| | Public read-only (GET) route: confirm it returns only public data | Semgrep `dp-sec-001-readonly` | warning |
| DP-SEC-002 | Permission callback whose only check is a nonce (`wp_verify_nonce`/`check_ajax_referer`/`check_admin_referer`) | Semgrep `dp-sec-002` | error |
| DP-SEC-003 | `wp_ajax_nopriv_*` / `admin_post_nopriv_*` handler: every one needs a justification | Semgrep `dp-sec-003` | error |
| DP-SEC-004 | Request value sets `post_status`, `post_type`, `perm`, `has_password`… (array key, `$args[...] =`, `$query->set()`) | Semgrep `dp-sec-004` | error |
| | Request chooses queried IDs (`p`, `post__in`, `post_parent`, `author`…) | Semgrep `dp-sec-004-ids` | warning |
| | Whole query args from the request (Bricks CVE-2026-118804 pattern) | Semgrep `dp-sec-004-whole-args` | error |
| DP-SEC-005 | `eval`, `create_function`, string `assert` | Semgrep `dp-sec-005` | error |
| | Request chooses a callable/class, or reaches `do_shortcode`, `extract`, `parse_str` | Semgrep `dp-sec-005-taint` | error |
| DP-SEC-006 | Request/cookie data reaches `unserialize`/`maybe_unserialize` | Semgrep `dp-sec-006` | error |
| DP-SEC-007 | Request-derived URL in `wp_remote_*`, `download_url`, cURL (SSRF) | Semgrep `dp-sec-007` | error |
| DP-SEC-008 | Request-derived path in include/require, file read, write, delete, `get_template_part`, `extractTo` | Semgrep `dp-sec-008` | error |
| DP-SEC-009 | `$wpdb` query without `prepare()`; placeholder misuse | PHPCS `WordPress.DB.PreparedSQL`, `WordPress.DB.PreparedSQLPlaceholders` | error |
| DP-SEC-010 | Unescaped output | PHPCS `WordPress.Security.EscapeOutput` (without `ExceptionNotEscaped`) | error |
| DP-SEC-011 | `$_POST` processing without nonce (`Missing`); `$_GET` without nonce (`Recommended`) | PHPCS `WordPress.Security.NonceVerification` | error / warning |
| DP-SEC-012 | Unsanitized or unvalidated input (`MissingUnslash` is a warning) | PHPCS `WordPress.Security.ValidatedSanitizedInput` | error |
| DP-SEC-013 | Meta key that looks secret/personal registered with `show_in_rest` | Semgrep `dp-sec-013` | error |
| | Any other meta with `show_in_rest`: it is public, confirm | Semgrep `dp-sec-013-review` | warning |
| | Secret-looking key sent to the browser (`wp_localize_script`, `wp_add_inline_script`) | Semgrep `dp-sec-013-localize` | error |
| DP-SEC-014 | `move_uploaded_file` without `wp_check_filetype_and_ext`; `'test_type' => false` | Semgrep `dp-sec-014` | warning |
| | SVG or executable type added to allowed upload types | Semgrep `dp-sec-014-mimes` | warning |
| DP-SEC-015 | Handler with a nonce check and a write, but no capability check (Subscriber+ missing authorization) | Semgrep `dp-sec-015` | warning (error after pilot) |
| DP-SEC-016 | Request chooses the option/meta key, role or capability that is written | Semgrep `dp-sec-016` | error |
| | Whole request passed to `wp_insert_user` / `wp_update_user` | Semgrep `dp-sec-016-userdata` | error |
| DP-SEC-017 | `is_admin()` used as authorization (permission callbacks, `'permission_callback' => 'is_admin'`, request handlers that write) | Semgrep `dp-sec-017` | error |
| DP-SEC-018 | Signature/token/hash compared with `==`, `===`, `strcmp` instead of `hash_equals` | Semgrep `dp-sec-018` | warning |
| DP-SEC-019 | Request-controlled redirect target in `wp_redirect`/`header()` | Semgrep `dp-sec-019` | error |
| | Any `wp_redirect()` (prefer `wp_safe_redirect()`) | PHPCS `WordPress.Security.SafeRedirect` | warning |

Fixtures: `tests/fixtures/DP-SEC-NNN/bad.php` (must fire on the lines marked `// expect: <rule>`) and
`good.php` (must produce no finding at all, from any rule).

### Notes on specific rules

- **013:** `register_meta()` without `auth_callback` falls back to `__return_false` for protected (`_`) keys and to
  `__return_true` otherwise. The bigger risk is **reading**: the core docs describe `show_in_rest` as "can be
  considered public" ([register_meta](https://developer.wordpress.org/reference/functions/register_meta/)).
  So the rule looks at `show_in_rest`, not at a missing `auth_callback`.
- **014:** `wp_handle_upload()` and `media_handle_upload()` check the type by default. The rule flags the cases
  that bypass that check.
- **015** starts as a warning. After the pilot on dp-schema and aic-blocks it becomes an error (in `v1.1`).
- **018** matches on names (`signature`, `token`, `hash`…). It cannot know that `$expected === $provided`
  compares secrets.

## Allowlists the taint rules understand

```php
$type = in_array( $type, $allowed, true ) ? $type : 'post';      // ternary
if ( ! in_array( $key, $allowed, true ) ) { return; }             // guard (also array_key_exists, isset( $map[ $key ] ))
$cb   = isset( $map[ $key ] ) ? $map[ $key ] : 'strtolower';      // server-side map
$val  = dp_allowlist( $val, $allowed, 'default' );                // shared helper
```

`sanitize_text_field()` and `sanitize_key()` are **not** allowlists: `private` or `users_can_register` pass them.
For paths, `basename()`, `sanitize_file_name()`, `validate_file()` (guard) and `dp_safe_path()` count.
A `realpath()` + `strpos()` check alone is not recognized: use `basename()` too, or `dp_safe_path()`.

## Suppressing a reviewed finding

Every suppression names the rule and gives the reason:

```php
add_action( 'wp_ajax_nopriv_dp_lead', 'dp_lead' ); // nosemgrep: dp-sec-003 -- public form; nonce + rate limit; no state change beyond insert into dp_leads
echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- InnerBlocks content, already filtered by core
```

A REST argument validated by a schema `enum` is not visible to Semgrep. Use the in-code allowlist, or a
`nosemgrep` that points to the schema.

## Using it in a plugin or theme repo

1. Add `.github/workflows/security.yml`:

   ```yaml
   name: security
   on: [push, pull_request]
   permissions:
     contents: read
   jobs:
     dp-security:
       uses: dpteodor-alt/dp-security-standards/.github/workflows/security.yml@v1
   ```

2. First run on existing code: create the baseline once.

   ```yaml
       uses: dpteodor-alt/dp-security-standards/.github/workflows/security.yml@v1
       with:
         mode: baseline
   ```

   Run it manually (add `workflow_dispatch:` to `on:`). Download the `dp-security-baseline` artifact and commit it
   as `.dp-security/baseline.json`. Then remove `mode: baseline`.

3. Optional: project helpers (custom escaping/sanitizing functions) in `.dp-security/phpcs.xml`:

   ```xml
   <?xml version="1.0"?>
   <ruleset name="DPSecurity-project">
       <rule ref="../.dp-security-standards/phpcs/ruleset.xml"/>
       <rule ref="WordPress.Security.EscapeOutput">
           <properties>
               <property name="customEscapingFunctions" type="array" extend="true">
                   <element value="aic_esc_svg"/>
               </property>
           </properties>
       </rule>
   </ruleset>
   ```

Inputs of the reusable workflow: `standards-ref` (default `v1`), `standards-repo`, `paths` (default `.`),
`baseline` (default `.dp-security/baseline.json`), `fail-on-warnings` (default `false`), `mode` (`check` or `baseline`).

### Baseline

`bin/dp-gate.py` merges the PHPCS and Semgrep JSON reports. It identifies each finding by
`sha1(tool | rule | path | normalized source line | occurrence)`, without the line number. Code that moves up or
down stays known; a new vulnerable line is new. `tests/run.sh` tests exactly this. When findings get fixed, the
summary says so; regenerate the baseline to lock in the progress.

Semgrep ignores `tests/`, `vendor/` and `node_modules/` when it scans a directory.

## Running locally

```bash
composer install            # PHPCS 3.13.6, WPCS 3.4.1, PHPCSUtils 1.2.3, PHPCSExtra 1.5.1 (+ PHPCompatibilityWP 2.1.8 dev)
pipx install semgrep==1.184.0
tests/run.sh                # fixtures + gate self-test
```

Scan a plugin with the same tools:

```bash
vendor/bin/phpcs --standard=phpcs/ruleset.xml /path/to/plugin
semgrep scan --config semgrep/dp-sec.yml --metrics=off /path/to/plugin
composer compat -- /path/to/plugin    # PHP compatibility report, not part of the gate
```

## Tool versions

| Tool | Version | Pinned in | Note |
| --- | --- | --- | --- |
| PHP_CodeSniffer | 3.13.6 | `composer.json` | PHPCS 4.0.4 exists, but WPCS 3.4.1 requires `^3.13.5` |
| WordPress Coding Standards | 3.4.1 (2026-07-27) | `composer.json` | |
| PHPCSUtils / PHPCSExtra | 1.2.3 / 1.5.1 | `composer.json` | required by WPCS |
| PHPCompatibilityWP | 2.1.8 | `composer.json` (dev) | brings PHPCompatibility 9.3.5 (no PHP 8 sniffs); 3.0.0 is still alpha |
| Semgrep CE | 1.184.0 | `tools.env` | |

## Known limits

- Semgrep CE taint tracking stays inside one function: flows through helper functions or across files are missed.
- Callbacks given by name (`[ $this, 'check' ]`, `'my_check'`) are not resolved to their body (001, 002, 003).
  002 and 017 recognize permission functions by name (`*_permissions_check`, `can_*`, `*_can_*`, `authorize`).
- Calls written with a leading backslash (`\update_option()`, `\register_rest_route()`) are not matched yet.
- `register_rest_route()` arguments built in a variable first are not inspected by 001.
- 002 accepts `is_user_logged_in()` as a real check. 015 still flags writes behind a nonce without a capability.

## Versioning

Tags follow `vMAJOR.MINOR.PATCH`. The moving tag `v1` points to the latest `v1.x.y`. Consumer repos use `@v1`, so a
rule change never reaches every repo at once: a stricter rule ships as a new minor version, and `v1` moves after
the pilot. A breaking change (rule removed, error added without a baseline path) means `v2`.

Every new rule needs: an ID, a `bad.php` with `// expect:` markers, a `good.php` that stays silent, a catalog row
here, and a link back to the Watch entry that taught it.
