# HarnessyXO v0.6.83

**Test targets in Environment:** open **Workspace Environment → Test targets** to connect a device or create/manage a VM. **Shell**, **Web UI** and **Desktop** now open tabs in the main area. OpenWrt can set up emulated Wi-Fi radios; Bluetooth emulation requires a custom guest with the necessary kernel and BlueZ support. The model receives requested versus verified capabilities and their emulation limits.

**OpenWrt startup and diagnostics:** readiness works with minimal images that lack `hostname`. SSH success, shell readiness and optional radio setup are separate stages, and readiness retries have a four-minute wall-clock limit after VM launch. Support downloads now include `TARGET_LOGS.json`, `TARGET_TIMELINE.json` and separately retained target events, with bounded boot/host-agent evidence. An SSH post-quantum warning alone does not make a successful readiness check fail.

**Updates from your private GitHub repo:** `python3 run.py` now checks [effishen/HarnessyXO](https://github.com/effishen/HarnessyXO) before starting the app. On macOS and Linux, a clean installation on `main` receives fast-forward updates and restarts the launcher before importing the updated code. Your settings, cached dependencies and workspaces stay in place. See [Startup updates](#startup-updates) for the one-time GitHub login and ZIP upgrade instructions.

**VM startup diagnostics:** download diagnostics as usual. `VM_LOGS.json` now lists available Lima guest boot and host-agent logs, collection limits and missing sources. Recognized technical boot, SSH and failure events are included by default; enable the existing content option for bounded raw log tails. Collection reads existing files without starting or stopping the VM or opening an application database.

Lima's native startup wait now follows HarnessyXO's 20-minute startup allowance, with a short outer cleanup grace. Earlier releases allowed 20 minutes in HarnessyXO but left Lima's readiness-event wait at its 10-minute default. Lima's individual guest requirements still have their own limits, so this change does not guarantee that an unavailable SSH server becomes ready. Startup evidence records the last recognized milestone, elapsed time and a bounded status observation after failure. It distinguishes HarnessyXO reaching its controller deadline from Lima returning a failure; an unknown native failure stays unknown. A successful manual retry can mean a late-ready guest or a recovered startup attempt; it does not prove that HarnessyXO missed a readiness signal.

**Automatic REA setup:** run `python3 run.py` as usual. On first launch, HarnessyXO downloads and installs [Reverse Engineer Anything](https://github.com/morluto/rea) 6.4.0 and, when needed, a private Node.js runtime. Later launches reuse the local setup. Agents can investigate native binaries, JavaScript/Electron applications and .NET assemblies through the normal tool catalogue; REA defaults to **Ask**. See [REA reverse engineering](#rea-reverse-engineering) for setup and scope.

**Storage concurrency fix:** existing workspace and machine databases now enable SQLite WAL during initialization, letting background reads coexist with message commits. Store connections close at the end of each operation. Attachment access checks read metadata rather than tool-result bodies; checkpoint badges inspect only relevant recovery prefixes and manifests. Recurring transcript/navigation reads run in a worker while UI updates stay on the event loop. Stop the old Harnessy instance before installing this release; keep its `.settings` and your workspaces.

**Useful support diagnostics:** download diagnostics as usual and open `SUMMARY.txt` first. It lists recent failures, failing code locations, database operation/wait timing, possible competing transactions or unfinished result cursors, and any tool that returned successfully before its result could be saved. `INCIDENTS.json` contains the corresponding structured evidence. Previous-session failures remain visible after a restart.

The default export retains traceback module/function/line, SQLite codes, generated connection/transaction identities, and stack samples collected during event-loop freezes. Database paths are represented by a stable identity hash; SQL, bound values, conversation content, source lines, frame locals and credentials remain excluded. Nearby operations and tracked candidates are explicitly distinguished from proven lock ownership. This release improves evidence collection; it does not change lock recovery or retry policy.

**OpenWrt 23.05.2** is available in **Workspace Environment → Test targets → Create VM → Operating system**, alongside OpenWrt 25.12.5. ARM64 and x86-64 targets use release-specific official kernel/rootfs downloads and pinned checksums.

Built-in model instructions now separate reasoning from factual recall: use logic to analyze evidence, assume facts recalled from training are outdated until verified, and check relevant external facts with web search and page reading before substantive work, including familiar facts. Sources must match the actual target versions, and fresh local observations guide environment claims. Web permission still controls access.

Workspace opening reuses already-correct Git history references. A locked history reference is preserved while the saved commit is protected through an independent reference, so active or abandoned reference locks do not require manual removal. Repeated opens reuse that protection, and file history remains reachable through Git garbage collection.

Existing v0.6 workspaces upgrade automatically when opened. The schema-14 format used by older v0.6 releases is upgraded to schema 15 in place, preserving project files, chats, memories, attachments and history. There is no need to create a new workspace or edit its metadata. This fixes the incorrect schema-14 rejection in v0.6.72.

Completed model/tool groups now create resume checkpoints. **State saved** appears on the group's final bubble once its conversation, owned project files/Git state, memories, task state and retained attachments have been saved and verified. A model response requesting several tools creates one checkpoint after the whole group finishes. Streaming, truncated and interrupted groups do not qualify.

Right-click a marked bubble and choose **Resume from here**. Confirm the selected boundary to restore its matching project/chat state and queue `continue`; the original prompt remains once in the retained history and its attachments are not submitted again. **Undo latest rewind** can recover the abandoned timeline and files. Missing or corrupt checkpoint data blocks restoration. Related managed background processes must finish or stop before capture or resume. These checkpoints cover managed project/chat state; remote device/service changes and live VM/process/browser state are outside that snapshot.

Unchanged file data and content-check receipts are reused. New large objects and attachments require a full content check, so checkpoint creation has some processing, disk and storage overhead. Existing bubbles without a complete group checkpoint do not become resumable retroactively.

**Jump to latest** keeps following when you switch away and return, including while a reply grows. The down arrow also keeps the navigator at its newest markers across chat rebuilds, tab switches and reloads. A queued Latest action stays saved through refresh handoffs; scrolling up still pauses and preserves your reading position.

The prompt navigator uses 10 px grey squares and clickable grey rectangles for markers above or below its visible window. Click a rectangle to reveal another page; click the up arrow to go to the beginning of the chat or the down arrow to jump to latest and follow. Wheel, touch, keyboard and Browse all remain available. Purple event squares and their menus retain their existing size and behavior.

Right-click a saved user prompt and choose **Delete prompt & everything after**. After confirmation, HarnessyXO removes that prompt and its following timeline and restores the project's files, memory, task state and attachments to the checkpoint immediately before it. The chat's active work stops and its queued prompts are cancelled. No replacement prompt is sent. **Undo latest rewind** restores the deleted state. Locked chats and prompts without a complete checkpoint cannot use this action; recorded external actions are shown because they cannot be reversed by a project checkpoint.

v0.6.65 makes the navigator consistent: every user prompt is a small grey rounded square. Selected events between prompts share a purple rounded square. A single event uses the same 7 px square; more entries increase it gradually to a maximum of 11 px. Clicking purple opens a pointed menu with the related prompt, event excerpts, colored icons, timestamps and icon-labelled counts. Every prompt remains individually reachable in long histories. The bottom down arrow still jumps to the latest messages.

v0.6.64 tunes context gradually from the history estimated in the current failing request. Recovery allows up to 24 smaller retries, with each reduction bounded to a small step; the fifth retry no longer halves history. Stable successful requests allow gradual capacity reassessment within your selected context setting. Failed upward trials introduce a longer cooldown, and all trials remain bounded. Stop interrupts recovery; a new prompt starts from its configured context setting.

A compact context-tuning log retains request estimates, backend-reported usage when available, rejection measurements, targets, counters and reasons across log rotation and app sessions. Estimated history, estimated whole input, actual backend input and the configured ceiling are labeled separately. Diagnostics exports include the retained tuning history and its retention limits.

The event menu follows **Settings → General → Prompt navigator**. Selecting an event takes you to its actual bubble so you can read the conversation above and below it. Context adjustments, errors, completion checks and other selected saved events have their own destinations. Prompts and bookmarks remain available. There are no **New** labels; event information remains available after a visit.

Prompt and event navigation show loading feedback immediately. **Jump to latest** retains your destination while a history refresh or initial restoration is in progress, including while the model or an approval request is waiting. A delayed navigation retains its request identity so a late response can complete it; **Retry navigation** is an explicit recovery action.

This release also corrects the queue and sidebar status when a completion check asks a project to continue working. The active run's **Completion Check** status appears only while the check runs; saved check events remain available in the timeline and navigator. Waiting projects identify the active blocker and its actual slot; continued work is described as **Continuing work**. Durable queued prompts keep their real queue position and requested slot. Attachment/package request detection avoids loading the entire transcript just to find the latest user prompt.

v0.6.62 introduced **Completion Check** in **Settings → General → Prompt navigator**, with a distinct marker for each saved check. It also stabilized the earlier inline groups. v0.6.63 retains the check option and uses the pointed event panel described above for group navigation.

v0.6.61 lets the queue proceed automatically when completion verification exhausts its available attempts. The affected project remains **Completion unconfirmed**, with its work, check conversation and retry controls preserved. Verification still runs first on the chat’s own model; valid CONTINUE decisions keep that project working. Continue or Retry after exhaustion uses the usual queue order.

v0.6.60 separates completion-check attempts from the total history. Each apparent final reply gets its own allowance of three attempts to obtain a valid decision, using that chat’s model. Successful new tool work renews the allowance for automatic continuation, so a long productive run does not stop simply because it has been checked three times. That release originally held unconfirmed endings for manual recovery; v0.6.61 replaces that policy for exhausted verification. The queue panel identifies the affected project.

v0.6.59 introduced inline **Compact groups**, replaced by the pointed event panel in v0.6.63 and by event-only groups in v0.6.65. The old layout preference remains readable for compatibility; both old values now preserve every grey prompt square and group selected events between prompts.

v0.6.58 restores a separate marker for every prompt. Long navigators scroll independently, with **Browse all** for a searchable list. In **Settings → General → Prompt navigator**, choose individual markers or compact groups, show or hide bookmarks, and select the status indicators you want. Status indicators are off by default; when enabled, their small badges leave the prompt marker or group count visible. Clicking a prompt or bookmark now retains the exact selected bubble through history loading and highlights it on arrival.

v0.6.57 checks every eligible final model reply, regardless of length. A neutral structured check must name an existing unfinished requirement and a concrete next action before continuing, with a run-wide limit that v0.6.60 replaces with per-reply attempts and a no-progress guard. New runs also select a bounded, coherent recent portion of an oversized previous turn when it fits, reducing wholesale loss of detailed working context. Run-owned approvals are retained.

v0.6.54 adds **Settings → General → Login session timeout**. The default is **Never**, replacing the fixed 12-hour sign-out. Choose a timed duration if desired and Save. A changed duration starts a new timer for currently valid sessions; it is a session time limit, not an inactivity timer. This setting applies to all users. Explicit logout, password/account changes and restarting HarnessyXO still end sessions.

v0.6.53 retries a backend-reported GPU hang once per run, after a five-second wait, when the failed request has not generated any answer, thinking, or tool-call output. The failed request keeps its slot and completed project work. Other queued runs pause until recovery succeeds. If the retry fails or is stopped, the queue stays paused across reloads and restarts; after recovering the model server, use **Run queue → Resume queue**. Slow prompt processing alone does not trigger this recovery, and HarnessyXO does not restart the model server. In v0.6.61, exhausted GPU recovery during completion verification is an exception: that project remains unconfirmed and releases its own finished recovery hold so other queued work can proceed.

v0.6.52 clears the superseded run’s retry notice when Edit & replace timeline commits. While replacement is waiting or restoring, only its progress is shown; cancelling or failing before restoration leaves the original retry available. Remaining retry cards identify a previous run and make clear that retry is optional. Stop followed by a fresh prompt still resets Auto context to the configured ceiling.

v0.6.50 keeps each left-sidebar project name, ID, and current or queued status inside one selectable row. Click the name or status to open the project; use **Run queue** to manage pending requests. Long titles retain their full row width, and idle projects keep their compact height. Missing terminal browser assets now return HTTP 404 instead of a successful JSON response that the browser could attempt to execute as JavaScript.

Run startup and completion update the sidebar in place, so a project click sent during those transitions keeps its navigation target. A new project's automatic title still updates when its run finishes.

v0.6.49 aligns timeline-replacement progress and its spinner with the chat column. While a replacement waits for related project files, its status identifies the blocking project and any current agent slot. Background history saving is identified separately from active generation; the replacement receives its own queue position only after restoration.

Completion verification is required in **Settings → Agent / Tools**. Every nonempty, tool-free apparent final reply is checked, regardless of length. The chat’s own model returns strict JSON: COMPLETE, CONTINUE with a specific unmet requirement and next action, or NEEDS_INPUT with a question. HarnessyXO parses that decision; it does not judge task completion itself. The expandable check bubble shows the original reply, instruction, response, optional thinking and separate attempt/history counts. An unreadable decision allows three attempts for that reply. Two automatic resumes without new successful tool work pause for review; a successful distinct tool invocation renews that allowance. Repeating the same tool and arguments, failed tools and extra prose do not renew it. Verification holds unrelated queued and already-waiting work while it runs. If its automatic attempts are exhausted, the project remains **Completion unconfirmed** and other eligible queued work can start automatically. **Run queue → Continue project** retains the recorded model and saved conversation, while **Retry this prompt** retains the original prompt and attachments. Both use the usual queue order after exhaustion. **Resume queue** remains available for other settled holds, such as interrupted runs. Stop cancels the run and releases its completion hold. An exhausted GPU retry during verification releases that run’s completed recovery hold as well. Recovery holds belonging to other runs, in-progress retries, ordinary generation failures and application/storage failures retain their separate policy.

v0.6.46 halves the automatic text-paste attachment threshold from **32,000 to 16,000 characters per paste**. At or above the threshold, the complete pasted text becomes a private `.txt` attachment; smaller pastes stay in the composer. The browser measures JavaScript string length (UTF-16 code units), so some characters such as emoji count as two. Attachment delivery and context budgeting are unchanged: conversion does not itself guarantee a token reduction.

**Retry after a stopped run sends `continue` in the existing conversation.** Use the stopped-run notice or **Project / Chat run queue → Recent attempts**. Phone **RETRY <code>** uses the same behavior. The original prompt and attachments stay in history; they are not added as a new request. Files, memories, saved work and the current composer draft remain intact. The continuation keeps the saved model profile and thinking setting and uses normal queue order. A queued request cancelled before it ever started still starts its saved request, because it has no earlier run to continue.

v0.6.44 fixes a ghost **Starting · waiting for transcript save** card during queued runs. Once a prompt is saved, the card disappears even if that message is outside the displayed history window or the browser has not refreshed the transcript yet. It stays retired after tab changes or page reloads. A genuine startup card now offers **Stop run**, while pending prompts retain their removal control.

v0.6.43 also moves the earlier **project write-lock wait and timeline restoration** out of the dialog. Confirming closes the dialog immediately. Progress and Cancel remain visible above the chat composer, including when viewing an older part of the conversation. You can switch projects or reload the page while the background operation waits. The status names the project holding the lock; after restoration, the persistent run queue takes over.

v0.6.42 sends **Edit & replace timeline** through the persistent run queue after restoration. The dialog finishes without waiting for an agent slot. The queued card keeps the edited prompt and attachments visible while you switch tabs or reload, and the job retains the selected model and thinking setting. Remove that queued prompt to cancel it before it starts.

v0.6.41 keeps the sidebar project highlight in sync with project-owned tabs. Selecting a chat, its Project Files tab or a file opened from that panel highlights the corresponding project and workspace. Closing the active tab or restoring an open session uses the same selection behavior.

v0.6.40 shows **Auto cap** in the chat's bottom status bar. It follows the retained-history target of each model request, including automatic reductions and larger trials. Hover or focus it for the exact token count and selected ceiling. **Last auto cap** identifies a finished run or saved request; **Auto cap pending** means the new run has not prepared its request yet.

v0.6.39 repairs context recovery when a prefill abort is followed by oMLX's HTTP 507 model-loading memory rejection. HarnessyXO waits and retries that same request while the backend clears memory, then resumes gradual context reduction if the prompt is rejected. The activity card distinguishes model loading from prompt capacity. Rough token estimates guide compaction but no longer block a preserved request before the backend can evaluate it.

HarnessyXO is a local-first browser workspace for long-running LLM work. It combines persistent chats, canonical project files, an isolated Linux VM, structured tools, durable memory, file history, queues, notifications, and inspectable run statistics.

HarnessyXO is local-LLM-first, not backend-bound. Core behavior remains provider-neutral and works with a generic OpenAI-compatible endpoint; oMLX, Ollama, llama.cpp, and future adapters may add more precise telemetry or advice only when a generic fallback remains. HarnessyXO never silently changes backend/model settings. The permanent boundary is documented in [Backend architecture invariant](#backend-architecture).

For the product story, design rationale, and concrete differentiators, see [Why HarnessyXO](FEATURES.md#why-harnessyxo).

v0.6.38 puts **Model for replacement** and **Thinking for replacement** inside the **Edit & replace timeline** dialog. Confirming applies both selections to the replacement and subsequent messages; Cancel leaves the chat settings alone. Hover the small information icon beside You, Thinking, HarnessyXO or Tool to see the recorded model and thinking setting for that bubble. Newly saved messages retain their settings after model/profile changes and reloads. Older messages show recorded fields where available and **Not recorded** for missing details; Model default remains an unspecified backend default.

v0.6.37 replaces the per-OS VM buttons with **External/Test Targets → Create VM**, a searchable OS selector and a compact, filterable target list. The catalog includes Ubuntu 24.04/26.04, Debian 13, Fedora 44, Kali 2026.2, OpenWrt 25.12.5 and Windows 11. OpenWrt uses an ash shell and LuCI web interface; other Linux guests offer Bash and Xfce/VNC. Test targets retain internet access and remain separate from the model's working VM. Settings now have compact navigation in narrow windows, and the UI pass improves dialog scrolling, long labels, icon accessibility and keyboard navigation. See [Test targets](#externaltest-targets) for host prerequisites and verification limits.

v0.6.36 adds a normal-chat workflow for code that depends on the user's target environment. The agent is instructed to identify the actual build/run system, inspect accessible targets itself, or provide short read-only commands so the user can paste the complete version report into chat. Dependent implementation waits for missing facts; known setups and portable/non-code tasks do not need a questionnaire. Version-sensitive choices use evidence for the installed version, and web sources carry retrieval dates. See [Target environment checks](#target-environment-checks). These are built-in model instructions, not a claim that every model will always follow them.

In **Settings → Models**, choose the default model for new projects/chats and each model's default thinking. Existing saved chat selections are preserved; switching to another model applies that model's thinking default. Double-click a project/chat in the sidebar to open its Project Files folder. One click continues to open the chat.

v0.6.34 rechecks an inconclusive VM file receipt after an applied Project file edit. A shared file's metadata can shift between the guest's before/after checks, producing exit 75 without a guest hash. HarnessyXO now retries only the VM read, up to four times, and confirms the host still has the written bytes before accepting a matching guest hash. It never replays the edit. A changed host file, a confirmed host/guest byte mismatch, or four unstable VM reads still stops the run. An already stopped run is not resumed automatically; inspect the last Project file edit before sending Continue.

v0.6.33 repairs a watchdog blind spot from v0.6.32. When two oMLX jobs overlap and the first job already has its own backend request ID, HarnessyXO continues polling progress for that exact request. Its accurate per-request Prompt Processing and tok/s counters can resume, including after the other job stops. A genuinely static request still has the 600-second prefill silence limit. An active backend request that reaches that limit is now described as active in the error card, without calling it abandoned. No automatic retry is sent.

v0.6.32 opens chats with one sidebar click and highlights the matching workspace/chat when you switch chat tabs. Workspace rows only open Environment on a double click. Overlapping oMLX or Ollama requests no longer display the same backend-wide live prompt counter in multiple chats; each request still shows its own final usage. Password SSH targets now create a private executable launcher for OpenSSH at connection time, even when an archive extractor strips the helper's executable permission. Existing saved credentials remain in the private host `.settings` folder. The root account retains full privileges on its remote host.

v0.6.30 leaves completed files in the canonical `Files/Project-XXXX` folder and tells you their exact paths. A normal deliverable no longer triggers `attach_file` or a duplicate chat snapshot. The tool is offered only when your latest message explicitly asks for a separate chat attachment or direct download of a single file; an unrequested call is blocked. The Project File Explorer can already open and download files in place. During inference, “Generating next action” means the last visible Thinking/Answer text stopped changing; the backend may still be assembling a structured tool call, and a fresh call-wide tokens/second rate indicates recent decoder activity, not a hidden Answer bubble.

Chats have green tabs, workspace environments purple tabs, and file explorers blue tabs. Other tool views have their own accents. The active tab retains a visible accent strip. App, workspace, chat and file context menus group related actions with horizontal rules. Click a sidebar chat once to open it and highlight its workspace; switching chat tabs updates the matching sidebar highlights. A workspace row opens Environment on a double click, and a missing workspace cannot open an Environment tab.

v0.6.28 keeps the complete queued prompt visible in its chat while it waits, including after switching tabs or refreshing the page. The prompt lives in the persisted queue until the agent checkpoints it as a saved User message; it is not sent to the model while waiting. A failed start before that checkpoint retains a dismissible copy of the sent prompt in the chat. The composer dropdown offers Auto or a specific Global Agent Slot when at least two slots are configured. A selected slot remains the job's admission target across restarts; unrelated Auto jobs can use another free slot. Reducing the configured slot count turns any pending preference for a removed slot back to Auto.

v0.6.27 fixes a retained-context recovery gap seen on a live oMLX request in v0.6.26. The new diagnostics show a recognized prefill-memory abort following a 250-character reasoning delta, which blocked tuning because the stream adapter required one exact synthetic-notice wrapper. The adapter now recognizes equivalent wrapper variants only when their complete abort detail matches the structured backend error; unconfirmed output still prevents replay. The diagnostics confirm Auto / 262,144 on that request, with approximately 182,238 estimated input tokens. Custom 200,000 would still allow that input; a lower Custom ceiling can reduce the request immediately while automatic recovery handles the capacity error.

v0.6.26 fixes two routes that could prevent prefill recovery. An oMLX activity-dashboard entry disappearing no longer counts as proof that a stream died: queued, transitional, incomplete, or unrelated activity can produce that gap. Quiet prefill retains the shared 600-second no-progress allowance. A backend error arriving at a watchdog deadline is delivered to recovery before any inferred stall. An oMLX synthetic `[Error: Request aborted: ...]` delta followed by the matching structured abort is recognized as a server notice, so it cannot incorrectly block context retries as if it were generated text. Real partial answers, reasoning, and tool calls retain their protection against replay.

**Custom sets a ceiling and remains subject to automatic adjustment.** Custom 200,000 can tune downward on capacity feedback and back upward after success, without exceeding 200,000. The GUI states this beside the Custom field. Presets and Maximum also use the same tuning under their selected ceilings. Saved profile values remain unchanged.

**Retained live context → Auto** starts from the configured/observed context window instead of half the window capped at 96,000. The final request still reserves output, system/tool costs, and the existing safety margin; 262K is a total window, not 262K of history plus everything else. All retention modes use backend feedback to tune within the job: reported token limits and predicted/allowed RAM inform small reductions, and comparable memory observations improve the estimate of fixed versus context-dependent memory. Reductions start from the current assembled-history estimate, use a bounded small step, and allow up to 24 retries. The fifth retry follows the same rule.

After stable successful requests near the current target, automatic tuning can try a small increase on a later normal model request. Failed upward trials increase the cooldown; an old rejection does not permanently prevent reassessment. Upward trials are bounded at 64 per job and rebuild eligible history from the saved transcript. Tuning remains local to that job and never writes a hidden saved profile limit. A new job or explicit retained-policy change starts a fresh search.

The shared implementation works with generic OpenAI-compatible, oMLX, Ollama, and llama.cpp transports. Native Ollama and generic HTTP/SSE errors now preserve the error payload instead of obscuring or ignoring it. Ordinary crashes/model-load failures are surfaced; shortening a prompt cannot necessarily shrink a backend's already allocated KV cache or fit oversized model weights. HarnessyXO does not silently restart/reconfigure a model server or workspace VM. VM instructions also distinguish real boot observations from static mount-lifetime flags and unsupported explanations about backend failures causing VM restarts.

v0.6.24 fixes a memory-recovery recognition gap: oMLX's `prefill_memory_aborted` error now enters the existing progressive context-tuning path, just like `prefill_memory_exceeded`. This works for structured HTTP errors and errors delivered inside a streaming response. Up to eight retries reduce the current run's retained context while preserving the saved profile. Retries apply before generated output, so a partially delivered answer or tool call is not replayed.

This includes v0.6.23's correction for delayed Bookmark availability on recently completed live bubbles. Thinking and reply bubbles become bookmarkable when their model response is saved; Tool bubbles become bookmarkable when their result is saved. There is no timer, minimum number of actions, or need to finish the entire agent run. Later alternating Thinking/reply segments retain their correct independent bookmark identities.

This includes v0.6.22's new-project startup fixes for large reference libraries. Startup observes file metadata instead of hashing and snapshotting all of References before contacting the model. It displays separate checkpoint, upstream-check, and request-preparation stages, with privacy-safe timing diagnostics. Owned-project checkpoints continue to save exact file content.

The integrated audit also fixes stale checkpoint reuse after a completed run, writer-lock cleanup on finalization errors and cancellation, unsafe File History restores, cross-project process control, an attachment-copy race, and malformed interview list fields. Persistent bubble bookmarks and isolated post-run history saving remain available. Existing v0.6 workspaces open directly; no rebuild is required.

## Workspace compatibility

Existing v0.6 workspaces remain compatible. Only workspaces from v0.5.x or earlier require a new workspace for the v0.6 line.

- There is no migration of old `Files`, private worktree, rewind, or `<ID>_output` layouts.
- A legacy workspace is rejected clearly and left untouched.
- Existing application settings and account records in `.settings` remain usable.
- Keep a copy of any older HarnessyXO release needed to open its corresponding workspaces.

## Install and start

Requirements:

- macOS or Linux
- Python 3.10 or newer
- Git for automatic source updates
- Internet access on first launch for Python packages and terminal browser assets
- Lima for isolated workspace VM features

Extract the ZIP into its own folder, open a terminal in that folder, and run:

```bash
python3 run.py
```

The launcher installs Python dependencies into the release-local `.vendor` folder, makes them available to its own prerequisite checks, prints Local and LAN addresses, and does not open a browser automatically. Open the printed address yourself.

### Startup updates

The source repository is private. Your computer needs its own GitHub access; granting access in ChatGPT does not sign your Mac into GitHub. The updater uses Git's existing credential helper or SSH agent and never asks you to put a token in the code or remote URL. With [GitHub CLI](https://cli.github.com/manual/gh_auth_login) installed, you can sign in once using:

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git --hostname github.com
```

You can also use an existing Git credential helper. GitHub CLI's [setup-git command](https://cli.github.com/manual/gh_auth_setup-git) configures that helper; the launcher itself needs Git, not GitHub CLI.

For a new installation:

```bash
git clone https://github.com/effishen/HarnessyXO.git
cd HarnessyXO
python3 run.py
```

For a ZIP installation, install the v0.6.83 package once. Close the old app, extract the new package into its own folder, and bring across your retained `.settings`; keep existing workspaces where they are. Launchers earlier than v0.6.82 cannot update themselves. The new launcher verifies the installed files and executable modes against the matching version tag before adding Git metadata to that folder. A modified or incomplete ZIP stays unchanged. Keep the package's `.github`, `scripts` and functional `skills` folders when extracting.

Later starts check the repository's `main` branch automatically. An applied update restarts `run.py`, then the normal dependency and REA checks run. If GitHub is unavailable, authentication has expired, tracked code has local edits, the checkout is on another branch, or history has diverged, the current installed app starts with an explanation. The updater preserves local changes and does not reset Git history. It will stop if an interrupted update leaves an incomplete source tree.

Only one process can use an installation folder at a time. Close the app before starting that folder again or replacing its application files. Automatic source updates currently support macOS and Linux; Windows skips the update check. This updates HarnessyXO's source from `main`; REA remains pinned to the supported 6.4.0 runtime and reuses its separate healthy cache.

On the first browser visit, HarnessyXO asks you to create the initial administrator account using the short one-time setup code printed in the terminal. Later visits use that username and password. Account controls are inside **Settings → Users / Password**. Passwords may be any non-empty length. All users are administrators in this release.

The default bind is `0.0.0.0:6767`. HarnessyXO requires username/password authentication and prints both Local and detected LAN addresses. Plain HTTP is not encrypted: use only a trusted private LAN, choose `127.0.0.1` for local-only access, or place HarnessyXO behind a trusted HTTPS reverse proxy. Never expose it directly to the public internet.

## The v0.6 project model

Each new workspace uses this physical layout:

```text
Workspace/
└── Files/
    ├── References/
    ├── Project-A7KM/
    ├── Project-B2QH/
    └── Project-C9VR/
```

- `Files/References` is the human-managed shared reference library. Models can read it but cannot modify it.
- Every project/chat has a four-character, non-confusable workspace-unique ID and one canonical `Files/Project-XXXX` directory.
- Notes, research, source, temporary work, and final deliverables all belong in that project directory.
- There is no separate output folder and no private active working copy.
- The workspace explorer, project-scoped explorer, structured file tools, Git/LSP, and VM all use the same canonical bytes.
- A model can write only its own project directory. Other unrelated projects are invisible to it.

The explorer may display a project title in small brackets beside `Project-XXXX`; that annotation is UI-only and does not change the filesystem name.

Uploading an archive to a chat extracts it into a uniquely named folder inside that chat's canonical project directory. It does not mount or select an alternate hidden working copy.

### Root projects

A new root project receives a fresh chat, fresh owned memory, and an empty project directory. Its model-visible namespace contains:

```text
/workspace/Files/References/        read-only
/workspace/Files/Project-XXXX/      read/write
```

### Child projects

Use **Create child project** when new work depends on files or durable knowledge maintained by an existing project. A child receives:

- a fresh independent chat;
- fresh child-owned durable memory;
- an empty writable `Project-YYYY` directory;
- live read-only access to the current parent and ancestor files;
- live read-only retrieval of current parent and ancestor memory.

It does not copy the parent transcript, files, memory, or a historical prompt state. Inside the child namespace, its direct parent looks like a managed directory:

```text
/workspace/Files/Project-YYYY/                  child-owned, read/write
/workspace/Files/Project-YYYY/Project-XXXX/     live parent, read-only
```

Earlier ancestors are nested through that chain. HarnessyXO implements these views through managed path resolution and read-only VM projections, not an unrestricted host symlink.

The chat's **Project Files** panel opens at logical `/workspace/Files`. It shows `References`, that chat's own `Project-XXXX`, and any explicitly checked Project Access sources; unrelated and ungranted siblings remain hidden. Live parent and ancestor folders appear under the current project using the same nested logical paths the model sees. Direct Project Access sources appear at `/workspace/Files/Project-XXXX`. HarnessyXO resolves both forms to canonical host directories internally and enforces them read-only.

### Project Access and hierarchy editing

Right-click an active Project / Chat and choose **Project Access…** to select other active projects with checkboxes. Each checked source gives the destination:

- live read-only access to the source's canonical Project files;
- bounded, source-labelled search/read access to its saved chat history; and
- read-only access to attachments that are actually linked from that saved history.

The destination's sidebar row shows a green **Read: XXXX, YYYY +n** badge beside its own project ID whenever direct grants exist. Two source IDs remain visible in the compact row; `+n` reports any additional sources, and hovering the badge or project row shows every source title and ID. Projects without direct grants have no badge.

`Files/References` and `Files/Project-XXXX` now have an explicit model-facing provenance distinction. `Files/References` is the shared reference-library location. A `Project-XXXX` tree is working/artifact material created or collected by its own HarnessyXO Project / Chat entity. Asking the model to “look at Project-XXXX for reference” means to consult that separate project's work as secondary context; it does not claim that the vendor or user authored/provided it and does not make it authoritative vendor truth. Read-only describes access permission only. A specific file may be attributed differently only when the user explicitly identifies that file's origin or traceable file-specific provenance supports it.

Another project's unsent attachment drafts are never exposed. Access is direct and non-transitive: a destination's descendants do not inherit its checkboxes. Parenthood also continues to exclude the parent transcript unless that parent is explicitly checked in **Project Access…**. Grants can be changed only while the destination is idle, unlocked, and has no model-owned background process still running. Source projects, their files, histories, attachments, and IDs are never copied or made writable.

The same right-click menu provides **Make child of…** and, for an existing child, **Unchild**. These actions change only the selected project's incoming parent link. Its complete descendant subtree moves with it, while every project keeps its canonical directory, four-character ID, chat history, owned memory, files, and direct descendant links. Cycles are rejected, locked or running subtrees cannot move, and pin anchors remain enforced.

The child is expected to rely on current upstream material. If it creates derived work that breaks after the parent changes, that is useful evidence that reconciliation is required.

## Upstream changes and memory

There is no persistent “stale” badge and no manual catch-up button. Immediately before a run starts, HarnessyXO observes References and ancestor files using path/type, size, mode, inode/device, modification time, and change time, and compares ancestor memory with the last successful baseline. This conservatively detects normal filesystem changes, including same-size edits with preserved modification times, without reading entire disk images. It is a change signal, not proof of byte equality or a recovery snapshot. The first run after updating an older baseline may report a one-time observation change.

If files or memory changed, HarnessyXO privately tells the model which paths or durable memory entries were added, modified, or removed. The model is instructed to inspect the current authoritative state while answering the user's actual request. It should mention the upstream change only when it materially affects the result.

The baseline advances only after a successful run with unchanged observations and memory. Failed or cancelled runs try again next time. Child-owned memory is never automatically deleted when parent memory changes; provenance identifies potentially affected child entries so the child can reconcile them using current evidence. Startup no longer creates automatic whole-References history snapshots. Previously saved reference versions remain available; exact owned-project checkpoints, explicit restore safety snapshots, and archives retain full-content recovery.

Memory kinds are domain-neutral—findings, decisions, requirements, constraints, hypotheses, procedures, references, tasks, preferences, summaries, and other entries. “Reverse engineering” is not hardcoded as the project type.

## Instruction interview reliability

Multiline answers are valid. HarnessyXO JSON-encodes them before sending the interview context to the selected model. An answer is marked accepted only after the model returns a valid next-question decision. If the model instead returns malformed JSON or the request fails, the current question and exact answer remain editable and **Answer & Continue** is re-enabled.

The dialog keeps its model selector within bounds, groups setup material under **Interview context**, groups completed answers under **Interview answers (n)**, and uses internally scrollable answer boxes instead of unbounded autogrow. The larger **Question n of 12** label and question appear below the divider following **Ready for your answer.**

## Timeline display and operational events

Three **Show** pills just above the composer control Thinking, Tools, and Events independently. A colored pill shows full cards. Turning it off keeps each matching item in place as a cardless, paragraph-tight one-line status and horizontal rule; it does not remove the record. Active compact rows animate a fixed-width ellipsis, completed rows show their outcome and timing where available, and failures remain red. Clicking one compact row temporarily expands only that item. Prompts and final HarnessyXO answers always remain full.

These display choices persist for the signed-in username in that browser. Toggling them preserves follow-bottom behavior or the current reading anchor, and clears selections which would otherwise become invisible.

HarnessyXO records material hidden orchestration boundaries in the timeline:

- progressive request-time context tuning and its retry outcome;
- a saved retained-context change when an active job adopts it;
- automatic model continuation;
- model-slot waits longer than ten seconds;
- safety/infrastructure failures which block a run.

The context card includes the reason, estimated request tokens before and after, the current run-local recovery target, and the backend's measurements when available. Each reduction starts from the history actually assembled in the rejected request and takes a small step with 1,024-token granularity. Reported overages inform that step without causing a large jump. Up to 24 context-reduction retries are allowed per request. On success, the card shows the accepted input estimate and viable target; pending upward trials show their assembled estimate before the backend answers. HarnessyXO never silently overwrites the saved profile.

Saving **Retained live context** while a job is active applies it before that job's next model request or adaptive memory-guard retry. A request already prefilling or generating is never interrupted. Only `active_context_mode` and `active_context_tokens` are hot-loaded; model, endpoint, credentials, sampling, Thinking, output limit, and other profile fields remain the run-start snapshot. Changing the retained target rebuilds the next cache-stable context epoch from the complete saved transcript; it does not delete transcript, Workspace Memory, Current Task State, attachments, or Project Files. These event records are presentation-only: they are excluded from model messages, context/token budgets, and exports.

Routine output-route glyphs no longer appear beside every Thinking/answer header. A short warning or uncertainty marker remains only when the backend actually produced questionable channel evidence; detailed backend fields, channel order, warnings, and uncertainty data are available in completed Run Stats and diagnostics.

## Backend-neutral stream recovery and tuning reminders

Every supported transport now uses one shared stream-progress watchdog. Transport heartbeats are tracked separately from actual inference progress. After 30 seconds without new reasoning, answer, Tool-call, usage, or monotonic runtime progress, HarnessyXO performs a read-only health check and updates the live status; it does not cancel or retry at that point. Silent initial prefill/model startup has a 600-second ceiling, while a stream that already produced output has a 120-second ceiling. A provider adapter may stop earlier only after twice confirming that an exact request disappeared.

When a wait is abandoned, HarnessyXO preserves streamed Thinking/answer text, records a red timeline event, and does not automatically retry a generation or Tool call. Generic OpenAI-compatible servers retain the conservative fallback; oMLX, Ollama and llama.cpp contribute available runtime evidence without becoming requirements. oMLX dashboard presence can confirm activity, including waiting requests, but absence is inconclusive and cannot trigger early cancellation. Real protocol errors take priority over watchdog deadlines so recognized capacity failures can reach the shared tuning loop.

Observed output symptoms can create a non-blocking tuning reminder. For example, with **Maximum output tokens** set to 32,768, an oMLX reasoning-headroom reminder calculates **Thinking Budget 16,384** rather than applying a fixed global value. HarnessyXO never changes the setting. oMLX reminders also warn that changing the backend's own model settings should happen only while idle because doing so can unload the active model. This is separate from HarnessyXO's request-view-only retained-context control above.

## Bounded large-attachment analysis

Chat attachments remain in private `.harnessy` state and do not automatically appear in Project Files or the workspace VM. Large text should be inspected with a specific `search_attachment` query. A search now returns at most 24,000 content characters in total, defaults to four 4,000-character chunks, and returns no random whole-file samples when the query has no lexical match. `read_attachment` supplies one exact range and is capped at 32,000 characters, including for older calls which request the former 200,000-character limit.

When a retrieval result is compacted from the active model prompt, its compact record retains the attachment ID, query, ranges/counts, and an explicit statement that only the result—not the attachment—was compacted. HarnessyXO tells the model to re-run a narrower search instead of sequentially reconstructing the file. Repeated identical attachment searches also participate in the existing evidence-driven temporary retention mechanism.

For work which genuinely benefits from grep, parsers, or repeated VM analysis, `copy_attachment_to_project` deliberately copies the exact bytes into the current project's owned directory. It requires both **Attachments / retrieval** and **Filesystem write** permission, preserves the private original, rejects path traversal and read-only/upstream targets, never overwrites an existing Project file, detects a changing source, cleans cancelled copies, and produces whole-file SHA-256 plus host/VM verification receipts. Ordinary attachment inspection remains private and does not create Project files.

## Explicit Project / Chat exports

**Export Project / Chat** snapshots saved history directly and now presents a checklist instead of bundled labels such as “Main Responses + Activity Summaries.” Select User prompts, main responses, intermediate responses, Thinking, Tool calls/results, and referenced attachments independently. Intermediate, Thinking, and Tool rows each support **Original text**, **AI summary**, or deterministic **Counts only**; unchecking a row excludes it.

The default reproduces the earlier recommended export: original User prompts and main responses, with generated summaries for intermediate responses, Thinking, and Tool activity. **Generated project handover** is a separate export type with Brief, Standard, and Detailed lengths. The model selector appears only when a selected AI summary or handover needs inference. Raw saved metadata is available only for a complete Original-text transcript, preventing metadata from silently restoring a category that was unchecked. Attachment references can be excluded completely or optionally bundled, while timestamps, recorded model information, saved-record ranges, cancellation, background completion, and archived-chat export remain supported.

## Rewind, timeline replacement, and undo

A parent rewind changes only that parent's active chat, owned files, and owned memory. Children, their chats, their owned files, their memory, and queued prompts remain intact. Their live parent view changes immediately, and their next run receives a private upstream delta.

Exactly one persisted historical User prompt exposes the timeline-edit action; Thinking, Tool, HarnessyXO, event, blank-space, highlighted-text, and multi-bubble selections do not:

- **Edit & replace timeline** restores the state immediately before that prompt originally ran, replaces the prompt, and continues on the same project timeline.

Before switching, HarnessyXO saves a private recovery transaction. **Undo latest rewind** restores the abandoned chat rows, canonical project bytes, owned memory, and checkpoint state without ever pointing the active project at a hidden historical tree.

Every saved timeline bubble can also be right-clicked and **Bookmarked** independently. User prompts keep their grey squares, including bookmarked prompts. Other bookmarked locations appear in the purple event menu between prompts. Gold bookmark icons identify them inside the menu and **Browse all**. Thinking and HarnessyXO reply bubbles from the same saved response remain separate targets, including later alternating output segments. Selecting a bookmark locates the exact bubble even when its source message is outside the mounted transcript window. **Remove bookmark** clears it. Bookmarks are project UI state and never enter model context.

The prompt navigator keeps an independently scrollable grey square for every user prompt. Its top **Browse all** control searches every prompt, visible bookmark and enabled event category; the bottom triangle returns to the latest messages. **Settings → General → Prompt navigator** lets you hide bookmarks, enable **Completion Check**, or select error, context, attention, stop, recovery and approval categories. These choices affect only the purple event menus, and every prompt remains available.

Purple squares contain selected events between user prompts. Opening one animates a readable list to its right, with a pointer back to the square, a reference to the related original prompt, and icon-labelled counts. Each event has an icon, label, excerpt, time and exact destination. A successful jump closes the panel so the event is readable; reopening identifies the selected entry. A loading or failed jump keeps the panel available. Outside selection, another group, Latest or Top closes the previous panel. Grey and purple fills stay consistent when selected, with a teal selection outline. Keyboard controls and reduced motion remain supported.

Past errors describe saved occurrences, including failures followed by recovery; they do not necessarily mean the project is currently blocked. Hiding a category changes only the navigator and does not remove history or approval cards. Loading feedback and explicit Retry navigation help recover interrupted jumps without waiting for model or tool work to finish.

Rewind cannot reverse external side effects such as sent notifications, web requests, remote device actions, or arbitrary operating-system changes.

## File History

Right-click a file and choose **File History** to open a persistent application tab. It provides:

- every known distinct version in a left column;
- current/deleted state and originating project/prompt where available;
- content or image preview and metadata on the right;
- compare with the previous version or current version;
- exact historical-version download;
- restore as a new copy;
- replace current after confirmation and a safety snapshot;
- a workspace history browser for paths that are currently deleted.

History is private app recovery data outside model-visible `Files`. It is never mounted in the VM or exposed as an LLM tool. Restores write bytes back into the canonical current project tree.

## Permanent archive

Archive is an irreversible record operation, not a reversible organizer.

Archiving a project archives that project and its entire active descendant subtree. HarnessyXO seals their chats, files, memory, dependency structure, relevant history, queued-run metadata, and the external upstream/reference state needed to understand what they saw. The family appears under **Archives** as a read-only tree, and its active project directories are removed after verification.

Project Access remains a live relationship between separate projects rather than ownership. Permanently archiving either endpoint revokes the live grant and records its former grant row in the sealed database snapshot; it does not copy the other project's whole transcript or files into the archived family.

Archiving a middle child leaves its active parent and siblings in place. There is no Unarchive action and archived items cannot be dragged back to Active. Archived roots can be reordered within **Archives**. **Delete archive family** permanently erases the complete sealed root and every archived descendant together, even when invoked from one descendant; it never unarchives a project.

## Global Agent Slots and overnight queues

**Settings → Agent / Tools → Global Agent Slots** is the normal concurrency control for both complete chat coordinators and temporary subagents:

```text
running coordinators + running subagents <= Global Agent Slots
```

With one slot, complete queued jobs run strictly one after another. If the active coordinator delegates, it suspends, transfers the sole slot to the subagent, resumes after the result, and still finishes before the next queued project starts.

With two or more slots, independent projects may run in parallel, or a coordinator may use spare capacity for read-only subagents. A parent and any descendant never run simultaneously, regardless of free capacity. A Project Access destination also serializes with its live source projects so it cannot read one while that source is being mutated. A blocked queue item does not prevent an unrelated safe item from using a free slot.

Ask for delegation in the prompt when useful; there is no per-message agent-count selector. `delegate_task` workers are temporary, read-only, tool-free advisers. They do not receive sidebar projects and cannot commit durable files or memory; the coordinator integrates their findings.

The composer dropdown offers **Add to global run queue · Auto** or **Queue for Slot N** (when multiple slots are configured). Auto starts on any free, safe slot. A specific slot waits for that slot even when another is free; it does not reserve the slot while waiting. Jobs remain in one global queue, with blocked jobs skipped so unrelated safe work can use capacity. The full queued prompt, its attachments, queue position, and slot choice remain visible in its chat across tab switches/reloads. When the agent checkpoints the User prompt and that saved message appears in the timeline, its queue preview goes away. A failed start before checkpointing retains a dismissible copy of the sent text. Sidebar badges show `Q#n` or running state, and the queue panel can inspect full prompts, cancel, or stop jobs. The chat footer shows `Agents: active / limit` and opens the agent/queue view. Slot choice affects complete queued coordinator runs; subagent placement and backend inference capacity remain governed by their own controls.

### Backend model capacity

Global Agent Slots is the HarnessyXO scheduling ceiling, not a claim about GPU capacity. Each model profile also has an advanced **Backend concurrent model requests** limit.

For example, Global Agent Slots = 2 with oMLX concurrency = 1 permits two agents to exist and perform safe tool work, while their actual model generations serialize through the one-request backend. True parallel inference requires backend support and enough memory.

## Run statistics

The final **Completed in …** control on an answer opens run-specific statistics. It distinguishes wall-clock duration from accumulated work and includes coordinator/subagent model time, Tool time, queue and slot waits, Thinking/answer phases, tokens, TTFT, cache data, output-channel provenance, speed provenance, and configured cost where available.

## Lock and pin

- Pinning preserves an item at its current relative sidebar position and replaces its drag handle with a pin. It does not move the item to the top.
- Locking makes that project's owned chat, files, and memory read-only. Creating a child remains allowed. Its live upstream view can still change, and it reconciles after unlock on its next run.

The project title and four-character ID are rendered as one selectable sidebar object.

## Explicit packaging and downloads

HarnessyXO creates ZIPs only when the user explicitly asks for packaging/export. A requested package is written into the current project's canonical directory. Ordinary file delivery should use direct download and does not trigger an unsolicited ZIP.

Packaging runs off the UI event loop, supports cancellation, and cleans incomplete archives. A model request for a Python script should produce the script, not repeatedly package the workspace unless the current user request explicitly asks for an archive.

## Notifications

Settings can configure ntfy completion/failure notifications without opening an inbound port. HarnessyXO can generate a secret topic, show a phone subscription QR, and send a test. Error alerts show a brief error reason, with secret URLs, credentials, request bodies and paths removed. Prompts, answers, reasoning and Tool content are excluded.

With **Accept ntfy messages as replies** enabled, an enabled error or stopped-run alert supplies **RETRY <code>** to send continue in its existing conversation and **STATUS <code>** to check recovery. Codes identify that exact stopped run even when another project sends a newer alert. Enable **Manually stopped or step limit reached** to receive stopped-run alerts and their continuation codes. They expire with the configured reply window or a HarnessyXO restart. A different server or topic, changed timelines and locked or archived projects reject retries. Missing original attachments or model profiles produce an explanation instead of a partial retry. A retry uses the normal run queue, retains the original attachments in history and preserves saved work. It clears only that failed run's backend hold; other admission holds remain. Check that the model server is ready before retrying.

Recovery sends preparation, queue and retry updates. Confirmed output sends **Running again** once, then that recovered run remains quiet through completion until another error. Automatic GPU or memory recovery sends brief state changes without requiring a reply. A backend request still reported active is not offered for remote replay; finish or stop it in the backend first. Normal completion notifications still follow their setting for runs that did not need recovery.

Two-way ntfy replies are opt-in. A phone reply routes to the project associated with the newest delivered run notification: idle projects start normally; active projects receive the reply through their safe follow-up queue. Treat the topic as a secret because reply mode grants remote prompt authority.

## VM and tool safety model

HarnessyXO uses a workspace VM for model shell/process/Git/LSP actions. For v0.6 project commands it creates one retained, project-isolated mount/PID namespace with only:

- the current canonical project writable;
- References read-only;
- the live ancestor chain read-only; and
- explicitly granted Project Access sources read-only.

Raw host workspace mounts, unrelated and ungranted projects, application settings, private history, archive storage, and other projects' namespace-controller records are detached from that namespace. Structured path resolution separately enforces the same ownership rules. Changing Project Access or ancestry changes the retained view signature, so HarnessyXO replaces that project's isolated namespace automatically on its next Tool use without requiring a whole-VM restart.

The namespace is reused by `run_command`, processes, Git, and code-intelligence work for the same project. A successful mount therefore remains available to later Tool calls until explicitly unmounted. It is intentionally recreated after an owned/ancestor project-root replacement such as rewind, and it ends when the workspace VM stops or rebuilds. The shell performs its final `cd` after login profiles and verifies the actual physical path before executing the model command.

Kernel/FUSE/loop mounts are VM-runtime overlays. Shell/process commands see the mounted contents; the browser File Explorer and host-backed structured file tools continue to show the underlying canonical project directory. Copy anything that must become a normal downloadable/history-tracked project file from the mount into a separate unmounted directory.

This is defense in depth; use dedicated non-privileged external-device accounts and normal host backups for high-value data.

## Settings and private application state

Machine-wide application state lives beside the release under `.settings`; it contains account records, registered workspaces, preferences, and scheduler state. On POSIX systems HarnessyXO creates this directory as private `0700` and safely tightens an existing same-owner directory when a shared umask made it too permissive. Wrong-owner and symlinked settings roots remain rejected. Each workspace keeps its database, uploads, history, rewind transactions, and permanent archives in `Workspace/.harnessy`, beside—not inside—`Workspace/Files`. Both locations are excluded from the model-visible project namespace. Do not move either structure into `Files`.

Use HarnessyXO's diagnostics export when troubleshooting. Credentials, password material, notification topics, and other secret-named fields are excluded or redacted.

## Documentation and release packaging

This package has three living documentation files: `README.md` for setup, operation and current verification; `FEATURES.md` for capabilities and product rationale; and `CHANGELOG.md` for release history. The eight `skills/*/SKILL.md` files are functional app resources: 11 Markdown files in total. Tests, test configuration, development dependency lists, historical handovers, standalone verification reports, audits, incident notes and QC archives are excluded throughout the application repository and ZIP. Keep this layout for future releases; do not move superseded documents into an archive folder inside the package. The release workflow builds committed application files, publishes matching version notes, and downloads the published assets again to verify their hashes.

Useful references: [backend architecture](#backend-architecture), [test targets](#externaltest-targets), [target environment checks](#target-environment-checks), [thinking controls](#thinking-controls), and [current verification](#verification).

## Backend architecture

HarnessyXO is **local-LLM-first and backend-agnostic**.

“Local-LLM-first” means the product should make long local inference practical: visible prefill/generation state, context and memory controls, cache-aware workflows, useful tuning reminders, and recovery that respects expensive model work.

It does **not** mean HarnessyXO is attached to oMLX, Ollama, llama.cpp, or any other server. A user may point an OpenAI-compatible profile at any implementation they choose.

### Required design boundary

- Core chat, agent, timeline, recovery, persistence, and export behavior must work through provider-neutral events and errors.
- Provider adapters may add capability evidence, request-scoped health, native telemetry, or a more precise recommendation.
- Every provider-specific enhancement must retain a safe generic fallback.
- Provider capabilities must be detected or explicitly configured; they must not be inferred from a model name alone.
- A health endpoint being reachable does not prove that a particular generation is alive.
- HarnessyXO may recommend a backend/model setting, but must never apply one silently.
- Advice is contextual, non-blocking timeline information which follows the Events display control and remains outside model context and exports.
- Tests for shared behavior must include a generic transport. Provider-specific regression tests are additional, not substitutes.

The HarnessyXO-only **Retained live context** policy is the narrow exception to the normal run-start profile snapshot: its mode/token ceiling may be hot-loaded at a safe boundary because it changes only HarnessyXO's next request view. It does not reconfigure, unload, or mutate the backend. All backend/model fields remain fixed for the running job.

### Stream recovery policy

The shared transport watchdog separately observes transport bytes/heartbeats and actual inference progress (reasoning, answer, Tool-call fragments, usage, and monotonic runtime counters).

- After 30 seconds without inference progress, HarnessyXO performs a read-only health check and updates live status. It does not cancel or retry merely because this threshold was reached.
- Before any model output, quiet prefill/model startup is allowed up to 600 seconds.
- After output begins, 120 seconds without progress is treated as an abandoned stream.
- A provider adapter may end the wait earlier only with authoritative request-scoped evidence, confirmed twice. A missing UUID in oMLX's best-effort activity dashboard is inconclusive; queue/phase transitions, partial snapshots and model-level correlation can all lose the observed entry. Include waiting/other activity in positive presence checks, but use the shared bounded silence fallback for absence, as for generic OpenAI-compatible and stock Ollama reachability.
- A protocol error already received in the current queue item outranks an inferred watchdog timeout, even when no subsequent terminal frame has arrived. Preserve the real backend error for capacity recovery.
- Partial Thinking/answer output is preserved. Automatic generation retry remains off because it can duplicate model work or Tool calls.

### Tuning reminders

Reminders are derived from observed symptoms plus the active profile. For example, when reasoning consumes most of a 32,768-token output allowance, an oMLX-capable profile may be reminded to try a 16,384-token Thinking Budget. The calculation comes from the profile’s current maximum output; it is not a global hardcoded model setting.

Provider-specific operational cautions belong in the reminder. For oMLX, the backend's own model settings should be saved only while idle because applying them can unload the active model and an in-flight request cannot resume. That is distinct from HarnessyXO's request-view-only retained-context policy.

An exact normalized `prefill_memory_exceeded` failure before generated output may progressively reduce only the run-local request view. The client maps both admission rejection and the provider's `prefill_memory_aborted` condition to this common code, retaining the raw provider error. A narrow text fallback covers the backend's explicit mid-prefill memory-guard wording in streaming errors without a structured code. Generic server failures, ordinary cancellation, and unrelated memory failures do not enter this path.

Targets use up to 24 retries per model request and 1,024-token granularity. Each reduction starts from the estimated history actually assembled in the failing request, bounded by its current target. Reported token limits and predicted/permitted memory inform the next small reduction; two comparable observations can estimate fixed allocation and variable bytes per estimated input token. The reduction remains bounded even when the predicted overage is large. Missing feedback uses the same gradual bound; retry five has no special halving. Backend tokenizer counts and Harnessy estimates remain distinct measurements. Rounded human-readable usage is not treated as a predicted peak. If the failing request already emitted reasoning, answer text, or tool-call fragments, preserve the failure without automatically replaying those outputs.

Auto starts from the full effective context budget. Custom, presets, Maximum, and legacy ceilings use the same provider-neutral adaptive search. All modes track accepted/rejected assembled-history estimates within one job. Stable acceptance near the current target can schedule a small upward trial on a subsequent natural request, rebuilding eligible saved history. A historical rejection is not a permanent ceiling. Failed trials increase the success cooldown, and at most 64 upward trials are allowed per job. Every trial respects the selected ceiling and observed runtime. Smaller requests do not prove the whole target fits; append runway is accounted for separately from observed history. Profile settings are never overwritten. Explicit retained-policy changes and new jobs clear learned tuning state.

A natural upward trial rebuilds eligible history at the candidate budget without subtracting a further append runway. This ensures the trial actually tests the larger assembled history instead of increasing a nominal target while sending less input. Fixed instructions, output reserve, safety margin and hard model limits still apply. After the trial finishes, ordinary later pressure can reserve append runway again. Coherent message packing can make assembled history smaller than its target; acceptance records only the actual estimate sent.

The compact context-tuning ledger records per-request estimates, reported native usage, rejection measurements, adjustments, counters and lifecycle events without retaining request bodies. It has bounded independent rotation and cross-session retention. Diagnostics exports include this history and a retention manifest, allowing ordinary epoch rebuilds to be distinguished from capacity adjustments.

oMLX can emit a synthetic `[Error: Request aborted: ...]` content/reasoning delta before the corresponding structured prefill abort. Its adapter holds only a bounded opening candidate and suppresses it only if the structured error confirms the complete abort detail. The stream's reasoning/tool-call parser can alter wrapper characters, which are ignored when confirming the body. Unconfirmed candidates are flushed on success, unrelated/different errors, and transport failure; real preceding output and tool calls retain the replay guard. This provider normalization does not change the shared retry algorithm or classify arbitrary text as a recoverable error.

Generic OpenAI-compatible JSON/SSE and native Ollama HTTP/NDJSON errors preserve their original payload. Explicit `context_length_exceeded` and llama.cpp `exceed_context_size_error` conditions enter shared request-capacity recovery, with `n_ctx`/`n_prompt_tokens` used when present. Native Ollama's documented errors generally contain only an error string, while oMLX admission errors can include predicted/allowed bytes. oMLX mid-prefill aborts may provide only the limit. These are capability differences, not separate core tuning algorithms.

An ordinary model-load OOM or a server whose KV allocation is fixed by its startup context cannot necessarily be repaired by trimming the submitted history. Do not classify every memory/crash error as recoverable, silently alter server configuration, unload/restart the model, or restart the workspace VM. Explicit failures retain the backend's explanation for the user.

The specific oMLX HTTP 507 / null-code `Cannot load ... projected memory ... metalcap memory ceiling ... (current: ..., model: ...)` error observed in the 2026-09-27 diagnostics has a separate model-admission classification. Before generated output, retry the same request after 2, 5, 10, 20 and 30 seconds so temporary backend cleanup can finish. These waits have their own bounded counter and never consume the 24 context-reduction attempts. Model-load figures do not enter the prompt tuner; a subsequent actual prefill rejection resumes context reduction. Persistent admission pressure is reported as backend blocked with the current reason and allocation figures. Cancellation interrupts the wait without another request.

UTF-8 token estimates are planning inputs, not admission measurements. Compact retrievable history to the planned budget, preserve fixed instructions/latest input/incomplete calls, and send that request even if its estimate still exceeds the budget. Only actual backend rejection triggers capacity recovery. If the rejected request cannot be changed without cutting mandatory input, stop with that explanation rather than sending the identical request repeatedly.

Primary protocol references: [Ollama errors](https://docs.ollama.com/api/errors), [Ollama context allocation](https://docs.ollama.com/context-length), [oMLX memory error metadata](https://github.com/jundot/omlx/blob/main/omlx/engine_core.py), and [llama.cpp server context](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/server-context.cpp).

## External/Test Targets

Test targets are separate from the LLM's primary working VM. They receive copied test files, have outbound internet for updates and dependencies, and can be reset to stopped snapshots. Existing SSH devices remain available through **Connect device**.

### Create and find a target

Open **Workspace Environment → Test targets → Create VM**. The workspace menu's **External/Test Targets** shortcut opens that same tab. Search the **Operating system** selector, name the target and adjust CPU, RAM and disk. Each OS supplies its own defaults and limits. **Architecture and model access** contains the less frequently changed options. Creation does not replace an existing VM or change the workspace environment.

The target list has name/OS/host search and a target-type filter. Start, Stop, Shell and the graphical interface are on each card. Model access, radio settings and activity details expand when needed. **Activity and setup output** shows downloads and startup errors. Changing tabs leaves an operation running in the background.

| Guest | Shell / graphical interface | Host requirements | Image source |
| --- | --- | --- | --- |
| Ubuntu 24.04 LTS | Bash / optional Xfce over VNC | Lima 2.0+ and QEMU | Lima official Ubuntu image template |
| Ubuntu 26.04 LTS | Bash / optional Xfce over VNC | Lima 2.2+ and QEMU with this template | Lima official Ubuntu image template |
| Debian 13 | Bash / optional Xfce over VNC | Lima 2.2+ and QEMU with this template | Lima official Debian image template |
| Fedora 44 | Bash / optional Xfce over VNC | Lima 2.2+ and QEMU with this template | Lima official Fedora image template |
| Kali Linux 2026.2 | Bash / optional Xfce over VNC | Lima 2.0+ and QEMU | Official generic cloud archive, pinned SHA256 |
| OpenWrt 23.05.2 | ash / optional LuCI web UI | QEMU, OpenSSH and e2fsprogs | Official 23.05.2 kernel + ext4 rootfs, pinned SHA256 |
| OpenWrt 25.12.5 | ash / optional LuCI web UI | QEMU, OpenSSH and e2fsprogs | Official kernel + ext4 rootfs, pinned SHA256 |
| Windows 11 | PowerShell / optional VNC desktop | Lima 2.2+, QEMU and swtpm | Your English (United States) installer ISO |

All catalog entries support ARM64 and x86-64. Match the host architecture for acceleration; another architecture uses slower CPU emulation. These are generic virtual machines, not emulations of particular router or Raspberry Pi boards. Windows guest support remains experimental in Lima.

The shared prerequisite installer prepares Lima/QEMU where supported. Update Lima if its version or bundled template is too old. Windows requires a matching ISO path on the HarnessyXO host and your own licence. Official media: [ARM64](https://www.microsoft.com/software-download/windows11arm64), [x64](https://www.microsoft.com/software-download/windows11).

OpenWrt checks host tools before preparing its image. On macOS, missing packages can be installed with `brew install qemu e2fsprogs`; Homebrew's keg-only e2fsprogs path is discovered automatically. On Debian/Ubuntu hosts, the equivalent packages are `qemu-system-arm qemu-system-x86 e2fsprogs openssh-client`. Startup reports missing tools without trying to obtain host administrator privileges through the browser.

### Shells, GUI and updates

**Shell** opens an interactive terminal in a main-area tab, labelled with the target. Model command/file tools use the same target. Switching tabs or reloading the browser keeps the backend session; explicitly closing the tab closes its shell. Managed guests allow package installation and guest system changes, including privileged commands; the external-device command filter still applies to connected physical/remote devices. Internet connectivity depends on the host's network and firewall.

**Desktop** opens the bundled noVNC viewer in a main-area tab. HarnessyXO forwards its selected guest display through your signed-in session, so the browser can be on another computer. Windows also offers a control to set the `harnessy` desktop sign-in password; that is separate from the VNC password. The bundled noVNC 1.6.0 source retains its upstream authorship and licence files.

OpenWrt uses **Web UI** for LuCI in a main-area tab, with the generated root password available in its connection controls. The guest page runs in an isolated iframe and its requests go through a session-bound proxy; guest scripts do not share HarnessyXO's browser origin. Closing the tab, signing out, stopping the VM or changing its display revokes the view. The ash shell authenticates with a dedicated private key; SSH password login is disabled. Two private QEMU networks separate LAN management from WAN internet. Only SSH and, when selected, LuCI are forwarded to host loopback. No TAP/bridge configuration is required.

### Emulated Wi-Fi and Bluetooth

OpenWrt's **Emulated radios** settings are available when creating a target and on its card. Stop an existing guest before changing the requested setup, then Start it. Optional setup failures leave its shell available and show the failed capability separately.

Wi-Fi setup installs `kmod-mac80211-hwsim` and `iw` from signed official feeds matching the installed OpenWrt release, then requests two virtual radios. It verifies the hwsim PHYs with sysfs and `iw` before reporting them active. Feed access, kernel ABI or package failures remain visible. Existing wireless, LAN/WAN and firewall configuration is retained; configure an AP/station test yourself using the guest tools you need. The [Linux hwsim documentation](https://wireless.docs.kernel.org/en/latest/en/users/drivers/mac80211_hwsim.html) describes supported software tests.

Bluetooth setup checks for BlueZ `btvirt` and Linux VHCI support. Stock OpenWrt 23.05.2 and 25.12.5 images do not supply the required combination, so they report unavailable. A custom image providing those prerequisites can start a dedicated guest service and verify virtual HCI controllers. HarnessyXO does not replace a stock guest kernel to enable this.

These are guest software radios. They cannot communicate over physical RF, discover nearby real networks/devices or test a particular USB dongle chipset/driver. `list_external_targets` labels requested setup and last observations; `target_status` performs a live probe. The model is instructed to carry these limits into its conclusions. Turning off requested setup leaves previously installed or user-created radios intact; live inspection still reports any emulated radios found.

### Startup evidence

OpenWrt readiness checks the first-boot marker, a working shell and a writable test root in one bounded SSH command. Hostname display uses a kernel fallback when the optional utility is missing. Permanent shell/root failures stop polling immediately. Ordinary boot retries have a 240-second wall-clock deadline after launch; image downloads, disk preparation and optional radio setup are separate timed stages.

Download diagnostics and open `SUMMARY.txt`. Target events have a dedicated bounded `targets.log` history and `TARGET_TIMELINE.json`, with operation IDs, stages, attempts, elapsed time and fixed failure codes. `TARGET_LOGS.json` reports which QEMU serial or Lima guest/host-agent files were included, missing, unsafe or limited. Collection reads existing files without contacting or starting a guest or opening its database. Default exports retain fixed technical signals; bounded raw tails require the existing content option. Credentials and view-capability URLs are redacted in both modes. Old diagnostic exports cannot gain evidence that their installed version never recorded.

OpenWrt package changes and configuration persist in an expanded writable ext4 disk. Its kernel is a pinned, separately booted file: a firmware `sysupgrade` or replacing the kernel from inside the guest is not supported by this controller. Choose OpenWrt 23.05.2 or 25.12.5 in Create VM to test either available release. The selected release determines the downloaded kernel/rootfs pair; create a separate target when changing releases. Other firmware releases require their verified kernel/rootfs pair in the catalog. Package installation and ordinary userspace updates are available in the existing VM. Kali's official base disk is 25 GiB, so the creator requires at least 30 GiB; its normal default is 40 GiB.

### Model access and files

The model uses `list_external_targets`, `target_status`, `target_exec`, `target_list_files`, `target_copy_to`, `target_copy_from` and `test_vm_control`. The last tool starts/stops a configured VM or creates/restores a stopped snapshot, then returns promptly. Poll `target_status` for progress. Creating and deleting VMs remain UI actions. Per-target availability/access and the global External/Test Targets permission both apply.

Test roots are `/home/harnessy/hx-test` for desktop Linux guests, `/root/hx-test` for OpenWrt and `C:/HarnessyTest` for Windows. Projects are not mounted into test guests. Copy inputs in and results back. Windows commands use PowerShell syntax; OpenWrt commands use ash, which does not provide Bash-specific syntax. Software inside these VMs can be installed independently of the working environment.

Guest images, credentials, controller state and snapshots live in private workspace metadata, outside model-visible project files. No host directory mounts or host SSH agent are provided. The VMs do have network access, including destinations allowed by the host's network.

### Stop, snapshots and removal

Stop requests guest shutdown, then powers off the VM if shutdown does not finish. During first boot, Stop can cancel startup once the VM instance exists. Normal application shutdown also stops managed test VMs.

Close the shell and graphical tabs, finish target commands, and stop the guest before taking/restoring a snapshot or deleting it. Snapshots copy the full stopped instance, including the disk and Windows firmware/TPM state or OpenWrt boot kernel and keys. Copy-on-write is used where supported. Restore replaces the guest's current state; project files and the working VM are separate. Removing an external device connection does not delete anything on that device. Removing a workspace first closes its target views and stops its guests; an unconfirmed stop keeps the workspace available.

### Source checks and validation

Catalog sources checked on 2026-09-25: [Lima templates](https://lima-vm.io/docs/templates/), [Kali cloud release](https://kali.download/cloud-images/kali-2026.2/), [Kali SHA256 sums](https://kali.download/cloud-images/kali-2026.2/SHA256SUMS), [OpenWrt ARM64](https://downloads.openwrt.org/releases/25.12.5/targets/armsr/armv8/), [OpenWrt x86-64](https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/), [OpenWrt QEMU startup source](https://github.com/openwrt/openwrt/blob/openwrt-25.12/scripts/qemustart), and [Fedora Xfce installation](https://fedoraproject.org/wiki/Xfce). Pinned source versions/checksums live in `environment/test_catalog.py`; existing disks are never replaced by catalog updates.

Current checks include a real OpenWrt 23.05.2 x86-64 QEMU boot, shell readiness with `hostname` absent, LuCI HTTP access, graceful stop and default serial-log diagnostics. The isolated test runtime required a test-only loopback TCP QMP adapter because it blocks Unix monitor sockets. Production uses the existing Unix monitor transport. Chromium checks cover the Environment/target tabs and isolated guest-page login, navigation and HTTP requests. Native macOS acceleration and the user's existing guest were not run here. See [Verification](#verification) for scope.

OpenWrt 23.05.2 sources and SHA256 pins checked on 2026-10-10: [ARM64 sums](https://downloads.openwrt.org/releases/23.05.2/targets/armsr/armv8/sha256sums) and [x86-64 sums](https://downloads.openwrt.org/releases/23.05.2/targets/x86/64/sha256sums). Current boot checks downloaded and verified the pinned x86-64 pair again.

## Target environment checks

This workflow applies when writing, modifying or debugging code/scripts and the target setup can change the correct implementation or validation. Ordinary questions, research, writing and summaries do not require an environment report. Portable code and an already established setup should not trigger unnecessary questions.

The built-in agent instructions establish this sequence:

1. Identify where the code will be built and run. Treat the HarnessyXO host, working VM, external/test target and final deployment machine as distinct environments.
2. Inspect supplied files, manifests, lockfiles and earlier project evidence to decide which facts matter. Inspect an accessible target directly using permitted tools.
3. If necessary facts are on an inaccessible machine, ask a concise question to establish its OS/shell, then provide a short set of read-only commands appropriate to the task. Label where to run them and accept the entire pasted output, including missing-command messages, in the normal chat.
4. Wait for missing facts before implementing dependent code. After receiving the report, summarize relevant versions/gaps and continue. Explicit user-approved assumptions remain possible.
5. Use official documentation, release notes, source or installed help matching the target version. Look up the current release when the task depends on what is latest. An unknown option or missing API should prompt inspection before another speculative variation.
6. Retain a compact target-specific finding with sources and observation/retrieval dates in project memory when permitted. Reuse applicable evidence; recheck when the environment changes, evidence conflicts or the task needs newer facts.

Commands are selected from the task rather than a universal inventory script. They should query only relevant OS, architecture, interpreter/virtual environment, runtime, toolchain and dependency versions. Version collection should not install/update software, download scripts, restart services or dump credentials and environment variables.

The project interview is unchanged. Existing chats receive these instructions on their next model request without editing or replacing their saved instructions. Web Off/Ask/On permissions still apply. Independent web-verification rules remain relevant to changing facts in non-code questions too.

`web_search` and `web_open` return `retrieved_at` in UTC. `web_find` reports the original cached retrieval date, not the time of the find operation. Older cached entries return `null` for an unknown date. Retrieval time is neither publication time nor proof of correctness/applicability.

This release adds instructions and source metadata, not a semantic enforcement gate. Tests confirm prompt delivery, pasted-output preservation, cache dates and permissions. They do not establish that every local model will consistently follow the workflow.

## Thinking controls

### Chat choice is not a model-profile default

Use **Settings → Models → Default model for new projects/chats** to select the starting model. Selecting a different profile for editing does not change this default. In each profile's **Profile** tab, choose **Default thinking for this model**. A new chat inherits that value. Existing settings migrate the previously active model into the explicit default model field.

An explicit Off/On/Low/Medium/highest choice is saved immediately when selected, before sending anything. The model profile ID and Thinking choice survive page reload, application restart and reopening a chat. Other chats have independent choices. Switching to a different model applies that model's default thinking; selecting the same model again preserves the chat's current choice. Editing a profile's default does not retroactively change saved chat selections.

**Model default always sends no Thinking override**, including when the profile's configured default is Medium or High. Verification can change the displayed label, never this stored intent or its outgoing request fields. The existing **Use profile preset** (`profile` in saved chat state) option continues to follow the profile's current setting explicitly. A preset that is itself Default also omits controls; invalid recursive values fail clearly. No settings, credentials or chat history are deleted or reset.

A chat already displaying a bare Medium may have a persisted explicit `medium` from an earlier release; that choice is retained. Select Model default in that chat to remove the override. Review the per-model defaults when upgrading: saved profile values are retained and now seed new chats.

### Labels and actual wire values

Qwen3.8 has model-level `low`, `medium` and `xhigh` effort. The UI now shows **xhigh**, including **Default · xhigh** when that default is verified. Canonical stored `high` keys remain stable for existing chats, profiles and verification records. `xhigh` input is accepted as the canonical-high alias. Generic models such as GPT-OSS retain High rather than being relabelled with Qwen terminology.

For a known Qwen compatible API configuration, canonical high maps to `reasoning_effort: xhigh` (or the configured reasoning/template-kwargs equivalent). Native Ollama's `think` parameter uses a different vocabulary. Its installed-endpoint verifier determines whether native `high` or `max` produces the Qwen xhigh rendering. **Displaying xhigh is not permission to send `think: "xhigh"` to an API which rejects it.** Explicit custom transport presets remain available and are identified as user configuration, not detected evidence.

Thinking headers use the recorded model identity to display its level name. Stats retains the canonical selection, model-facing display name, source (`model_default`, `chat`, or `profile_preset`), and actual wire fields separately. Historical request evidence is not rewritten using the current profile.

### Correct native renderer response contract

Ollama `ChatResponse.DebugInfo` has JSON name **`_debug_info`**. Its nested string is `rendered_template`. v0.2.40–41 mistakenly read `debug_info`, and the old shared mock repeated this mistake. A normal successful Ollama debug response could consequently be rejected as `no_render_proof` before any explicit-level samples ran.

The corrected parser prefers the official prefixed field, supports an unprefixed compatible response when the official field is absent, and rejects malformed/conflicting envelopes rather than silently masking them. It requires bounded template text, an assistant prefix, unambiguous system-level effort evidence and the appropriate open/closed Thinking prefix. Ordinary generated content or an HTTP 200 response does not establish a level.

The independent contract tests exercise actual field spellings rather than importing the old mock's response builder. Missing proof no longer implies an old server or absent Thinking capability. A reported version `0.0.0` is retained as reported but does not identify a particular build or its age. Recheck after changing such a server build, even when the version string remains unchanged.

### Installed server default versus stock model default

Stock Qwen3.8's reference template defaults to xhigh. This is not automatically the same as the value selected by a serving engine when an API parameter is omitted.

In the upstream Ollama source reviewed on 2026-09-10, the native chat route supplies boolean `true` when a thinking model receives no `think`. The `ThinkValue.String()` boolean path returns Medium; the Qwen renderer uses xhigh for a direct nil renderer input and native high/max, but uses no extra effort directive for Medium. The route's defaulting can therefore differ from calling the renderer/template directly. These source findings are **not proof of the user's custom build's runtime behavior**.

HarnessyXO measures omitted-parameter behavior separately from explicit levels. It must not silently set xhigh and call that “no override.” A corrected check may legitimately report Default · Medium for a server that applies that fallback. The tooltip distinguishes this server observation from stock Qwen's xhigh default. Explicitly selecting xhigh is the way to request the highest effort rather than follow an engine's differing default.

### Verification, persistence and limitations

Use **Settings → Models → Capabilities → Verify Thinking levels & default → Run check → Save**. Re-run after installing v0.2.42 because an old failed report cannot recover the rendered response that was discarded.

The manual check sends at most six fixed renderer-only requests: omitted Thinking, Off, low, medium, high and max. It sends neither user conversation nor workspace files. It may load the model, uses the existing model scheduler and confirmation, is bounded/cancellable, and blocks while agents are active. A server ignoring the debug flag receives a one-token output limit; the check stops on missing proof. Default and Off during ordinary chat, metadata discovery, and page reload do not start these extra probes.

The omitted sample is verified independently. Low/xhigh and explicitly marked Medium can be established from system directives. An unmarked Thinking prefix is **not** assumed to be Medium: its full render fingerprint must match the separately verified Medium reference. Conflicting effort directives and user-quoted markers do not prove a level. Off needs the appropriate closed prefix. Explicit-level mapping can remain unknown while a directly marked default is known, and vice versa.

A valid default report displays Default · xhigh/Medium/Low/Off with timestamp, effort and no-override tooltip. Insufficient/invalid/stale evidence remains Model default. Saved evidence is scoped to endpoint/model/credentials, available metadata and server version. A failed recheck clears the draft success; cancelling Settings does not overwrite saved settings. A successful check never replaces a chat's Default with a concrete level. Auto detection refreshes only the small selector and preserves the composer draft.

These are **last-verified static render observations**, not measurements of model-internal computation, quality, refusal behavior or generation speed. The current installed-endpoint verifier understands native Qwen3.8-style evidence, not every serving engine. Compatible API defaults remain unverified without a corresponding backend inspection method. No real user Ollama/Lima/native-NiceGUI integration was available in the implementation environment; synthetic contract tests are not a replacement for the user's installed-endpoint check.

### Primary references reviewed 2026-09-10

- Qwen template, supported effort names and default: https://huggingface.co/Qwen/Qwen3.8-27B/raw/main/chat_template.jinja
- Qwen model card and API example: https://huggingface.co/Qwen/Qwen3.8-27B
- Ollama API request/response structs, ThinkValue parsing and boolean conversion: https://raw.githubusercontent.com/ollama/ollama/main/api/types.go
- Ollama request defaulting and renderer-only chat response: https://raw.githubusercontent.com/ollama/ollama/main/server/routes.go
- Ollama Qwen3.8 renderer implementation (shared Qwen35 file): https://raw.githubusercontent.com/ollama/ollama/main/model/renderers/qwen35.go
- Upstream renderer tests, including nil default versus boolean true: https://raw.githubusercontent.com/ollama/ollama/main/model/renderers/qwen38_test.go
- Ollama Thinking controls: https://docs.ollama.com/capabilities/thinking

Current upstream source is not a substitute for the installed custom server. No weights, model import, server binary, VM or user workspace is changed by this release.

## REA reverse engineering

Run `python3 run.py` or the usual shell launcher. First launch automatically installs the pinned REA 6.4.0 package and its dependencies into HarnessyXO's retained settings directory. A supported existing Node.js installation is reused; when Node.js/npm is missing, setup downloads a private Node.js 24.21.0 runtime from the official distribution and verifies its pinned SHA-256 checksum before use. It does not install Node.js globally or require a separate REA installation command. Internet access is needed for the first setup; a healthy cached setup is reused on later launches. Keep `.settings` when replacing the application files.

If setup cannot finish, HarnessyXO still opens. Use **Settings → Agent / Tools → REA → Repair REA 6.4.0** to retry; **Check status** shows the local runtime and remediation. REA set to **Off** skips automatic setup, and a configured custom REA command is preserved. Opening or saving Settings and model tool calls do not install software. REA is not registered with other applications.

Native decompilation uses an existing Hopper, Ghidra or IDA installation; select **Auto**, or choose the intended engine. Automatic setup does not install those engines. Static JavaScript/Electron and .NET inspection use their own analysis paths. Advanced configuration accepts an existing local command, JSON arguments, selected environment values and a timeout; the default timeout allows a cold native import to finish. Existing Node.js must be 22.19+ within 22.x, 24.11+ within 24.x, or 26+; unsupported versions trigger private setup.

Put the target in the current Project Files, References or a project made visible through Project Access. Ask the agent, for example: “Use REA to inspect this application, trace how it constructs the identify command, and show the evidence.” The agent discovers `rea_status`, `rea_tools`, `rea_analyze` and `rea_query` through HarnessyXO's existing tool discovery. It can inspect functions, pseudocode, instructions, strings, callers, callees, cross-references, JavaScript application structure and managed metadata. Available queries depend on the installed provider and the selected target.

**REA reverse engineering** has the same **Off / Ask / On** controls as other tool families. Filesystem read permission also applies. Ask approves analysis of a selected target; follow-up queries stay within that run's authorized target. A different target needs a new analysis action. Stop and run completion close the owned REA session. Evidence retained by REA is session-bound; include useful findings in the project before finishing the run.

This integration exposes static investigation operations. REA's runtime execution, device control, browser attachment, arbitrary host commands, installation, patching and filesystem export operations are not model tools. Project paths and retained evidence are checked by HarnessyXO; source documents are inspected as inputs rather than executed. REA analysis runs on the host so it can use native engines. Its results go to whichever model backend you selected, with the same backend data handling as other HarnessyXO tools.

Tool results preserve REA's success/failure, evidence identifiers, coverage, limitations and remediation. Large results are bounded for the model; request narrower queries or retained-evidence views when a result reports truncation. Missing engines, unsupported targets or incomplete analysis do not become a claim that a feature was fully reverse engineered. Upstream setup and provider references: [installation](https://github.com/morluto/rea/blob/rea-agents-6.4.0/docs/installation.md), [MCP contracts](https://github.com/morluto/rea/blob/rea-agents-6.4.0/docs/mcp-contracts.md).

## Reading the diagnostics bundle

Download diagnostics using the existing UI action. Open SUMMARY.txt first; INCIDENTS.json links recorded errors with nearby SQLite operations, stall samples and scoped tool-result boundaries. After a restart, the summary also examines the bounded previous-session tail. EXPORT_METADATA.json records app/session/runtime versions and a timezone-aware collection time. DATABASE_STATE.json is the bounded registry in the collecting process; a separately launched recovery collector has its own registry and may report no live connections.

Workspace, machine-state and chat-export connections now record SQLite operation origins and codes, connection IDs, transaction IDs/ages/start actors, configured busy timeout/journal mode and candidate same-database transactions, unfinished result cursors or in-flight operations. Candidate presence is not proof of lock ownership. External processes, custom/uninstrumented connections and evicted tracking entries may remain unknown; registry limits and eviction counts are reported.

Exception and during-stall evidence includes reviewed code module/function/line only. Unknown external code retains a digest and line. No SQL, parameters, source text, frame locals, exception bodies, raw database paths or dynamic task names enter this evidence, including the optional content-rich export. Database logging has independent bounded retention and avoids the application's database. Logger/evidence failure does not replace database outcomes.

Tool events now include workspace/chat/run identifiers. A result-ready record is written before saving the tool message, so support can distinguish a completed tool from failed persistence. The independent stall monitor samples at most three times per stalled heartbeat and stops with application shutdown.

This release builds on v0.6.78 and retains its WAL/connection-lifetime fixes, reduced transcript reads and UI workers, as well as OpenWrt 23.05.2, workspace upgrades, history-lock protection, grouped checkpoints and existing retry/recovery policies. Existing database tables and saved data are retained. See [Verification](#verification) for actual checks and limits. Historical diagnostic ZIPs cannot retrospectively gain traceback or lock ownership information that was never recorded.

## Verification

The v0.6.83 focused gate completed with **128 passing checks** covering real-shell hostname fallback, bounded readiness and cancellation, radio setup/provenance, retained diagnostic evidence and privacy, target-tab persistence and lifecycle, and session-scoped HTTP/VNC transports. Chromium 155 checks exercised the rendered Environment controls, terminal/display tabs, reload persistence, isolated guest-page login/navigation/HTTP requests, and a noVNC RFB handshake with canvas rendering and logout disconnect. UI layout checks use controlled target fixtures. Separate real-guest browser checks passed OpenWrt LuCI login, populated dashboard data, System/Timezone navigation and session revocation.

A fresh pinned OpenWrt 23.05.2 x86-64 guest booted in 28.8 seconds under QEMU TCG, passed actual SSH readiness with `hostname` absent, reached LuCI and shut down gracefully. Its real serial log was collected in default technical-signal mode. The test runtime required a loopback TCP adapter for QMP; native macOS/ARM acceleration and production Unix-monitor behavior were not exercised here. Automatic Wi-Fi package setup failed because guest HTTPS was blocked by that runtime; the working shell was preserved. Separately provisioned, signed, ABI-matched official packages allowed the unchanged setup/probe to verify two real guest hwsim PHYs and interfaces, including after reboot. No real physical RF, native Bluetooth controller, or user's existing guest was tested.

This release retains the reader-versus-commit fix for the contention observed in the v0.6.77 diagnostics. Real SQLite tests hold a reader open while the workspace persists a tool result; the write completes in WAL mode. Separate writer-contention tests preserve SQLite's normal busy failures and diagnostic evidence. Store contexts commit/roll back and close on all tested paths; the generic diagnostics connection keeps native SQLite context semantics.

Regression checks cover prior-release workspace upgrades, exact grouped recovery and corruption rejection, attachment access ownership, chat exports, machine-state import, diagnostics privacy, and transcript navigation. Large-payload tests forbid unwanted transcript columns rather than relying only on timing. UI tests delay database reads and verify event-loop heartbeats and rejection of stale results after chat or viewport changes.

The v0.6.82 updater and launcher checks completed with **56 passing tests**. Real temporary Git repositories exercise fast-forward changes, local edits, divergent history, rejected incoming paths, ZIP/tag matching, ignored-file collisions, partial-update recovery and offline checks. Actual child processes verify that the installation lock survives both launcher/application exec steps, blocks a second launch and is released after exit. A pending update also blocks the direct application entry before Harnessy imports. These checks ran on Linux; no native macOS or Windows update run was performed here.

The preceding v0.6.81 selected release gate completed with **782 passing tests**, 8 optional tests skipped and two historical checks deselected. This includes 86 VM collection, export and startup evidence checks, plus existing SQLite, REA, UI, recovery and VM readiness checks.

The selected release gate deselects an actual Chromium navigator test that cannot run without a browser executable, and an old permission-label source assertion that also fails unchanged in earlier releases. Some older VM layout/projection tests still assert obsolete project paths and also fail unchanged in v0.6.80; they are outside this selection. These counts describe the selected release checks, not a claim that every historical repository test passes.

The pinned REA 6.4.0 server was also exercised directly: MCP initialization and tool discovery succeeded, and a real PE/CLI fixture passed .NET artifact inspection, member inspection and evidence retrieval through HarnessyXO's approval flow. JavaScript analysis reached REA but returned `capability_unavailable` because this build environment's process inspection command fails; its retained partial evidence remained readable. Native Hopper/Ghidra/IDA analysis was not run here. Transport regressions cover Stop, repeated cancellation, launch/close races, timeout, malformed/oversized messages, detached-provider EOF cleanup and concurrent setup. Path and tool-boundary checks are application controls; they do not provide an OS sandbox or an immutable snapshot of inputs while another process edits them.

Automatic setup was exercised on Linux x64 starting without Node.js on PATH. The launcher downloaded and verified official Node.js 24.21.0, installed REA 6.4.0, and completed .NET artifact/member inspection and evidence retrieval using that private runtime. A second launch passed with download and installation calls forbidden. Archive, cancellation and cache regressions cover safe extraction, platform identity, interrupted setup and shared setup locks. macOS and Windows installation use their pinned official archives; they were not executed on those hosts in this build environment.

VM diagnostics read up to eight workspaces and five fixed Lima log filenames, with 128 KiB tails per file and a 2 MiB aggregate VM-log bound. Workspace discovery is separately bounded and does not read a database. Default exports retain fixed technical signals and reviewed measurements, not arbitrary log lines; raw log tails require the existing content option. Missing, unsafe, empty, truncated and unrecognized sources remain visible in the collection report. Tails are observations at download time, not a guaranteed archive of every earlier boot. If a later startup replaces a log, earlier evidence may no longer be available.

The Lima startup option was checked against the supported upstream v2.2.0 source and [official command reference](https://lima-vm.io/docs/reference/limactl_start/). Automated checks exercise timeout, cancellation, native controller failure, later-running observations and guard enforcement. No live macOS Lima boot was performed in this build environment; the successful manual retry was reported by the user, not reproduced here.

### Storage and validation limits

WAL needs local storage with SQLite's locking/shared-memory support; a local external drive is suitable, while a network filesystem is not a supported workspace location. Initialization verifies that WAL was enabled. SQLite's default durability, busy timeout and automatic checkpoint settings are retained. Concurrent writers can still contend; the fix removes the demonstrated background-reader barrier rather than blindly retrying model/tool work.

Stop Harnessy and its VM before copying a whole workspace. Preserve the entire workspace, including private database state. Do not copy only `workspace.db` or remove `-wal`/`-shm` files from an active database. Chat export and legacy machine-state import use SQLite's coherent backup API, including committed WAL content.

No native macOS browser session or live oMLX run was performed in the build environment. Tests use real local SQLite databases and the native NiceGUI server-side objects with controlled delayed reads. Initial synchronous chat mounting and remaining auxiliary UI reads can still take time on unusually large or slow storage; recurring refresh/navigation reads are offloaded. This release does not claim to identify every external process lock holder or guarantee that SQLite can never report busy.

Package validation checks the three living Markdown documents plus eight functional skill files, version identity, executable modes, ZIP paths/CRC, and extraction hashes. `RELEASE_MANIFEST.json` records the delivered file hashes. No historical handover or QC archive is shipped.
