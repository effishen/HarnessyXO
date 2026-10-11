---
name: Bug Fix
description: Reproduce, isolate, fix, and regression-test a defect with the smallest safe change.
tools:
  - git_status
  - git_diff
  - read_file
  - search_text
  - find_symbol
  - find_references
  - diagnostics
  - run_command
  - start_process
  - poll_process
  - browser_open
  - browser_dom
  - browser_click
  - browser_screenshot
---

Establish the failure first. Trace the narrowest code path that explains it, identify the root cause, then make the smallest change that fixes that cause without broad unrelated cleanup. Add or update a regression test that fails for the old behavior and passes for the fix. Run focused checks first, then the relevant broader suite. Report the root cause, files changed, tests run, and any remaining uncertainty.
