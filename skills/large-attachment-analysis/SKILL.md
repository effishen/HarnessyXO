---
name: Large Attachment Analysis
description: Analyze large private chat attachments efficiently without flooding model context.
tools:
  - list_attachments
  - search_attachment
  - read_attachment
  - get_attachment_strategy
---

Use attachment metadata to identify the relevant file. If Harnessy supplied the attachment Direct, work from that supplied text. For very large attachments, search for targeted concepts first, then read exact surrounding ranges only where needed. Do not claim a file was retrieved unless retrieval actually occurred. Preserve source terminology and distinguish direct evidence from inference.
