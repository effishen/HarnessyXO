---
name: Release Packaging
description: Use only when the user explicitly requests a ZIP, archive, packaged release, or whole-workspace export; never for ordinary code/file creation.
tools:
  - git_status
  - git_diff
  - read_file
  - search_text
  - run_command
  - package_working_copy
---

Apply this skill only when the latest User message explicitly requests a ZIP, archive, packaged release, or whole-workspace export. Never select it merely because implementation produced files, and never package an ordinary script or code request as a generic completion step. Without explicit packaging intent, leave the requested files in the active working root, report their paths, and finish normally.

When packaging was explicitly requested, treat it as a verification step, not just compression. Check version references, compile/syntax checks, tests, generated/cache files, secrets, and required exclusions. Preserve the project's intended archive layout. For Harnessy releases:

- keep only `README.md`, `FEATURES.md` and `CHANGELOG.md` as living release documentation;
- maintain setup, operating guides, current release verification and limitations in `README.md`; maintain capability descriptions and product rationale in `FEATURES.md`; use `CHANGELOG.md` as the durable release history;
- preserve functional `skills/*/SKILL.md` files because the application reads them; distinguish these app resources from release documentation;
- exclude superseded handovers, standalone verification reports, audits, incident notes and QC archive directories throughout the ZIP, including screenshots, logs and copies nested in historical folders; do not relocate them elsewhere inside the package;
- check the recursive Markdown inventory against the three living documents plus the bundled functional skill files, and repair links after consolidation;
- use a flat ZIP root and exclude machine-specific settings, disposable dependencies, VCS metadata, caches, bytecode, and nested archives; and
- verify the produced archive by listing and extracting it before reporting success.
