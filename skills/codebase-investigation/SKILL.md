---
name: Codebase Investigation
description: Map an unfamiliar codebase systematically before proposing changes.
tools:
  - list_files
  - read_file
  - search_text
  - git_status
  - git_diff
  - find_symbol
  - find_references
  - go_to_definition
  - workspace_symbols
  - diagnostics
---

Inspect before changing anything. Start with project structure, entry points, configuration, and tests. Follow concrete symbols and call paths rather than guessing from filenames. Prefer structured Git and code-intelligence tools when they answer the question directly. Distinguish verified behavior from inference. Summarize the architecture, important files, risks, and the smallest sensible next step.
