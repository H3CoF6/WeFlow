---
name: weflow-overview-sync
description: Keep the WeFlow architecture overview document synchronized with code and interface changes. Use when editing WeFlow source files, Electron services, IPC contracts, DB access logic, export and analytics flows, or related docs that affect architecture, fields, or data paths.
---

# WeFlow Overview Sync

## Workflow

1. Read the architecture overview markdown at repo root before any WeFlow edit.
2. Identify touched files and impacted concepts (module, interface, data flow, field definition, export behavior).
3. Update the overview document in the same task when affected items are already documented.
4. Add a new subsection in the overview document when the requested change is not documented yet.
5. Preserve the existing formatting style of the overview document before finalizing:
- Keep heading hierarchy and numbering style consistent.
- Keep concise wording and use `-` list markers.
- Wrap file paths, APIs, and field names in backticks.
- Place new content in the logically matching section.
6. Re-check the overview document for format consistency and architecture accuracy before replying.

## Update Rules

- Update existing sections when they already cover the changed files or interfaces.
- Add missing coverage when new modules, IPC methods, SQL fields, or service flows appear.
- Avoid broad rewrites; apply focused edits that keep the document stable and scannable.
- Reflect any renamed path, API, or field immediately to prevent architecture drift.

## Collaboration and UI Rules

- If unrelated additions from other collaborators appear in files you edit, leave them as-is and focus only on the current task scope.
- For dropdown menu UI design, inspect and follow existing in-app dropdown patterns; do not use native browser dropdown styles.
- Do not use native styles for frontend UI design; implement consistent custom-styled components aligned with the product's existing visual system.
