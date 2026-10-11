---
name: Project Handover
description: Produce a concise, continuation-ready handover grounded in the current project state.
tools:
  - git_status
  - git_diff
  - list_files
  - read_file
  - search_text
  - get_tool_history
  - get_generation_metrics
  - remember
  - update_checkpoint
---

Inspect the current state rather than relying only on conversational recollection. Capture the baseline/version, completed work, important decisions, architecture constraints, known regressions, deferred items, verification status, and exact next work. Prefer concrete filenames and commands where they help continuation. Keep the handover operational: the next agent should be able to resume without asking the user to reconstruct prior decisions.
