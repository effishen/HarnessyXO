# Changelog

## v0.6.90

- Include scrubbed Lima host-agent and QEMU controller errors in the default diagnostics download, including unfamiliar error wording. Keep guest console output and command payloads excluded while preserving technical failure details such as permissions, memory, firmware, device properties and disk locks.
- Preserve bounded failed-start evidence before the next Start, Factory Reset or rebuild replaces the VM logs. Correlate controller commands and lifecycle operations, record the requested VM configuration, and distinguish launch-time resource snapshots from later export-time state. Retain test-target QEMU launcher errors as well as guest boot signals.
- Add HOST_STATE.json with available OS, CPU, memory/swap, cgroup limits, resource pressure, disk/inode space, application process state, KVM access, firmware metadata, known tool versions and Python dependency versions. Probes are read-only and report missing, unsupported or unsafe sources explicitly.
- Keep useful exception facts across cause chains: OS/DNS errors, process exit codes and signals, timeout durations, HTTP status, TLS verification codes and JSON error positions. Preserve reviewed run stop reasons and operation labels instead of reducing them to hashes.
- Add an export coverage ledger and retained technical evidence. State per-source read/export sizes, truncation, exclusions and collection failures; keep diagnostics available when an individual collector fails. Update the download dialog and support summary to describe the expanded default evidence.
- Preserve chat/file content and credential exclusions, existing VM lifecycle behavior, model progress and public startup updates. Leave README unchanged and keep the same 11 Markdown resources; private QA stays outside the application package.

## v0.6.89

- Show a shared model-request display across backends: animated waiting and request elapsed time, actual prompt-processing progress and cache counts when available, and an explicit unavailable state when the server supplies no progress. Keep the previous completed call's decode speed, prompt-processing speed and time to first output separate from current live metrics.
- Request native streamed prompt progress from llama.cpp. Count newly processed tokens against uncached work, handle fully cached prompts, preserve native timing precision and final usage, and keep concurrent request telemetry separate. Leave generic OpenAI-compatible requests free of llama.cpp-specific options.
- Refresh quiet-stream status after each health check and advance the displayed wait locally. Distinguish a reachable backend from confirmed request progress; repeated counters and transport heartbeats do not count as new model work. Preserve Stop and existing request deadlines without retrying generation.
- Lead support diagnostics with the current model request and include MODEL_REQUESTS.json. Retain bounded timestamps, local request correlation, numeric progress/usage/timings and fixed timing provenance without prompt, reasoning, response or tool-argument text. Label older evidence and incomplete coverage explicitly.
- Preserve existing VMs, tools, settings and public startup updates. Leave README unchanged and keep the same 11 Markdown resources; private QA stays outside the application package.

## v0.6.88

- Finish OpenWrt startup when QEMU has booted but its launcher output remains open. If the launch handoff times out, verify this target’s QMP identity and running state before continuing shell/bootstrap checks with the same ports and disk. Leave unverified state explicit instead of launching a replacement VM.
- Show a useful error for empty timeout exceptions: include the failed stage, time limit and diagnostic code. Show **Guest running · Start setup incomplete** when a live VM still needs setup, and offer **Retry Start** on its existing disk.
- Keep the installed OpenWrt package architecture priorities when installing Wi-Fi through isolated official feeds. This preserves image-specific priorities while keeping custom feeds isolated and normal signature and kernel checks in place.
- Explain launch timeouts and later successful guest probes together in diagnostics. Distinguish radio setup that was never reached from a failed package installation, and record verified launch recovery separately.
- Preserve existing guests, settings, radio helpers, automatic Linux Lima setup and public startup updates. Leave README unchanged and keep the same 11 Markdown resources.

## v0.6.87

- Enable **Emulated Bluetooth controllers** when creating an OpenWrt target. Checking it installs matching signed guest packages and sets up two software Bluetooth controllers automatically. Existing targets can use **Set up / repair radios**; no custom guest image or VM rebuild is required.
- Bundle verified static BlueZ controller helpers for ARM64, x86-64 and all supported MIPS variants. Keep both controllers in one emulator so they can communicate, and verify owned H4 transports and registered guest adapters before reporting activation. Include the helper source, build recipe and upstream source/licences. This is software emulation with no physical RF, nearby devices or USB dongle identity.
- Document the stock OpenWrt 25.12.5 BlueZ 5.83 `btmgmt` CLI failure and big-endian MIPS daemon management/scan-ioctl limitations, including an explicit HCI scan workaround in model guidance. Check HCI registration independently; do not equate it with complete daemon/profile compatibility.
- Show an animated loading indicator and indeterminate progress during VM startup, alongside the current stage and elapsed time. Stop animation on success, failure or cancellation, and respect reduced-motion preferences. Include Bluetooth package, emulator, attach and verification stages in progress and diagnostics.
- Automatically install a verified private Lima 2.2.1 distribution and matching guest agents on Linux ARM64/x86-64 hosts when `python3 run.py` or VM Create/Start finds it missing. Reuse the verified cache offline and restore its path for the app, keeping existing usable PATH installations and shell profiles intact. Preserve normal host-package privilege checks; Lima requires a normal user account.
- Preserve REA as an ordinary VM CLI, existing guest disks, network configuration, workspace data and the public updater. Leave README unchanged and keep the existing 11 Markdown resources. QA files stay outside the application package.

## v0.6.86

- Run REA as the ordinary `rea` CLI inside reverse-engineering workspace VMs. The LLM discovers installed commands through shell tools and CLI help; Shell commands and Long-running processes permissions apply. Remove the dedicated host MCP tools, permission and Settings panel, and stop host REA downloads in `python3 run.py`. Preserve inactive host settings and caches for rollback.
- Install or update REA in an existing VM through **Workspace Environment → Manage Optional Tools → Apply / Retry Selected** with REA selected. Resolve the latest published stable npm version, verify a supported guest Node runtime and staged CLI before switching, and retain a working guest installation if an update fails. Normal REA invocations reuse the installed version. Downloads respect public-outbound settings.
- Add **Set up / repair radios** for running OpenWrt targets and probe their current radio state after restarting HarnessyXO. Repair missing simulated Wi-Fi interfaces without overwriting guest network configuration. Show package, network, kernel and missing-prerequisite results in setup output and diagnostics; incomplete requested setup reports failure while keeping the shell available. Disable the Bluetooth checkbox for new stock images, which cannot supply VHCI/btvirt controllers; existing customized targets retain the option.
- Add release-specific OpenWrt MIPS Malta targets using pinned official kernel and ext4 downloads. OpenWrt 23.05.2 offers MIPS32 big-endian; 25.12.5 offers MIPS32 and MIPS64 in both endian variants. These use slower software CPU emulation with one CPU and at most 2048 MiB RAM; they do not emulate a particular router board or radio chipset.
- Preserve existing targets, workspace data and the public startup updater. Leave README unchanged and keep the existing 11 Markdown resources, with QA material outside the application package.

## v0.6.85

- Verify ZIP contents before restoring executable metadata lost during extraction, so an unchanged archive can join startup updates. Also verify untouched current-main ZIPs against their exact main commit; leave genuine source edits intact.
- Show which application file differs and why when a ZIP cannot be adopted. Keep bounded update evidence in `STARTUP.json` and the support summary instead of reporting only a generic skipped update.
- Fix REA setup on Linux systems using umask 0002. Create and publish managed runtime folders with safe permissions, and repair installer-owned cache permissions only beneath a private, owned REA root. Keep wrong-owner paths and unsafe redirects blocked.
- Report the specific REA storage component and reason in setup output and diagnostics. Preserve reviewed startup evidence across the launcher-to-app restart. Keep REA pinned to 6.4.0 and reuse healthy cached setup; app updates can change that supported pin.
- Preserve the public HTTPS updater, live target permissions, existing VMs and workspace data. Leave the user README unchanged and keep the existing 11 Markdown resources.

## v0.6.84

- Fetch startup updates on macOS and Linux from the now-public `effishen/HarnessyXO` repository over HTTPS without GitHub login, including existing installations whose saved origin uses SSH. Keep local edits, settings and workspace data intact.
- Apply saved tool permissions to active runs and pending approvals. External / Test Targets **On** allows tools for enabled targets without repeated confirmation; **Off**, explicit Deny and Stop still block execution. Other required permissions continue to apply.
- Keep newly saved permissions when another page opens tabs, selects a workspace or changes navigator/file-list preferences. Save only the settings owned by that action.
- Check missing, unknown and disabled targets before asking for approval. Return a target-selection error instead of showing a dialog for a call that cannot run.
- Add `PERMISSIONS.json` with content-free permission decisions and separate approval-wait timing, so support can distinguish a permission wait from slow guest execution.
- Preserve existing VMs, workspace data, radio capability reporting and REA. Leave README unchanged. Keep the same 11 Markdown files and exclude QA material from the app package.

## v0.6.83

- Move test-target management into **Workspace Environment → Test targets**. Open guest Shell, LuCI Web UI and VNC Desktop views in main-area tabs; retain workspace/target selections through browser reloads.
- Embed guest displays through session-bound transports and isolated browser frames. Close their access on tab closure, logout or VM lifecycle changes, and keep guest pages separate from HarnessyXO's browser origin.
- Fix OpenWrt readiness on minimal images without `hostname`. Check the bootstrap marker, shell and writable test root together; stop immediately on permanent failures and bound boot readiness retries to 240 seconds after launch.
- Add optional OpenWrt Wi-Fi simulation using matching signed packages and verified mac80211_hwsim radios. Check Bluetooth prerequisites for custom VHCI/btvirt images; stock images report unavailable. Tell the LLM which capabilities are requested or verified and their software-only limits.
- Add separately retained target lifecycle events, stage/attempt/timing evidence, `TARGET_TIMELINE.json` and bounded QEMU/Lima logs in `TARGET_LOGS.json`. Include display transport errors and previously missed SQLite lock events in support summaries, while redacting credentials in every export mode.
- Preserve settings, workspaces, existing guests, REA setup and private GitHub startup updates. Keep 11 Markdown files and exclude QA material from the app package.

## v0.6.82

- Check the private `effishen/HarnessyXO` repository when `python3 run.py` starts on macOS or Linux. Apply clean `main` fast-forward updates before importing the app and restart the launcher after a change.
- Use existing GitHub credentials on your computer. If the network, authentication or local history prevents an update, explain the reason and start the installed version while preserving local edits, settings, caches and workspaces.
- Verify ZIP application files against the matching version tag before adding Git metadata. Hold an installation lock through setup and the app; stop on incomplete source updates, including interrupted updates detected on the next launch.
- Publish matching version tags, GitHub Release notes and verified source ZIP/checksum downloads. Keep three living documents plus eight functional skill files; exclude tests and QA artifacts from the application repository and ZIP.
- Retain REA 6.4.0 automatic setup, actionable SQLite/VM diagnostics and existing workspace compatibility. Automatic source updates are currently limited to macOS and Linux.

## v0.6.81

- Include bounded Lima guest boot and host-agent log evidence in diagnostics. Report available, missing and limited sources in VM_LOGS.json; retain fixed technical signals by default and raw tails through the existing content option.
- Record startup milestones, controller exit/timing, timeout ownership and a bounded status observation after failure. Keep collection independent of application databases and avoid starting or stopping the VM during export.
- Pass the configured 20-minute startup wait to Lima instead of leaving its readiness-event wait at the 10-minute default. Keep individual guest-requirement deadlines, isolation checks and the existing stop-on-infrastructure-failure behavior.
- Retain automatic REA setup, SQLite fixes and the 11-Markdown-file package.

## v0.6.80

- Set up REA automatically when `python3 run.py` starts HarnessyXO. First launch installs the pinned 6.4.0 package; later launches reuse a healthy cached installation.
- Reuse supported local Node.js/npm, or download a private Node.js 24.21.0 runtime verified against the official release checksum. Keep runtime state beside retained settings, with no system-wide installation.
- Preserve custom REA commands and skip automatic setup when REA is Off. If setup fails, keep the app available and provide Repair REA in Settings.
- Stage and verify setup before publication, protect concurrent setup and cancellation, and check the runtime's host identity before reusing its cache. Retain the REA tool boundaries, evidence handling, SQLite fixes and 11-Markdown-file package.

## v0.6.79

- Integrate the pinned local REA 6.4.0 MCP server with backend-independent, discoverable analysis tools for native binaries, JavaScript/Electron applications and .NET assemblies.
- Add a REA settings panel with explicit runtime installation, status/remediation, native engine selection, timeout and advanced local configuration. Preserve existing settings and default the new tool family to Ask.
- Bind analysis and retained evidence to the current run and authorized Project Files target. Enforce filesystem read permissions, target/path checks and a fixed static query catalogue; keep REA's runtime/device/browser/host-command and file export actions outside model access.
- Preserve evidence, limitations and failure/remediation in bounded model results. Close owned MCP processes on completion, Stop, timeout or protocol failure without repeating failed analysis work.
- Retain v0.6.78's SQLite/WAL and UI-read fixes, useful diagnostics, prior workspace recovery and the 11-Markdown-file package layout.

## v0.6.78

- Enable SQLite WAL during workspace/machine initialization so a long background checkpoint read does not prevent committing a tool reply. Retain default durability, busy timeout and checkpoint settings; preserve ordinary writer contention errors.
- Close store-owned connections after native commit/rollback, including failed commits. Keep generic diagnostic connection semantics intact.
- Add a covering chat/role index for transcript counts. Read attachment authorization metadata without loading full tool-result content or tool-call JSON.
- Read checkpoint identities first, reject unusable boundaries early, and verify only relevant transcript prefixes and individual manifests. Retain full signature/object corruption checks before claiming a saved state.
- Offload recurring transcript/navigation database reads and guard UI publication against stale chat, render and viewport state.
- Import legacy machine databases through SQLite backup so uncheckpointed committed WAL rows are preserved; failed imports leave the original state available for retry.
- Keep the lean package layout: three living documentation files plus eight functional skill files; no old handovers or QC archives.

## v0.6.77

- Clean the distribution to three living documentation files and eight functional skill files. Fold current guides, rationale and verification into the living documents; exclude all historical handovers, audits and QC archives, including nested copies and screenshots. Update the packaging rule to prevent accumulation.

- Put a readable support summary and structured incident index at the front of diagnostic ZIPs, including bounded previous-session failure evidence after restart.
- Preserve reviewed exception chains and traceback locations, SQLite error codes, runtime/session versions and timezone-aware export metadata through default sanitization.
- Instrument workspace, machine-state and chat-export database access with hashed database identity, connection/transaction ownership and age, operation origin/duration, configured wait settings, and possible transaction/result-cursor competitors. Keep evidence content-free in both export modes.
- Sample the event-loop thread during a freeze with an independent bounded observer, while preserving the existing recovered-stall timing event.
- Record run/chat/tool scope and the successful result boundary before tool-result persistence, so a storage error cannot hide completed tool work.
- Keep collection independent of application databases and resilient to malformed logs. Preserve existing SQLite commit, rollback, timeout, journal, retry and connection-context behavior.

## v0.6.76

- Add OpenWrt 23.05.2 to the test VM creator for ARM64 and x86-64, alongside 25.12.5.
- Select verified release-specific kernel/ext4-rootfs pairs; retain checksum validation and existing target disks.
- Check and repair ext4 metadata after disk expansion; reject an unrepairable staging disk before creating the guest.

## v0.6.75

- Strengthen model instructions to assume training facts are outdated until verified, and to search and read authoritative sources before substantive work even for familiar facts.
- Distinguish logic and reasoning from factual recall, preserve observed target versions and local evidence, and reuse applicable sources within a run.
- Retain existing Web Off / Ask / On enforcement and honest reporting of unavailable verification.

## v0.6.74

- Reuse correct Git history references when opening a workspace instead of rewriting them. Preserve active and abandoned reference lock files.
- Protect required history commits through immutable independent references when the original reference is missing or differs. Reuse existing protection; use bounded unique protective names if the canonical pin is occupied or locked. Keep snapshot commits reachable during Git garbage collection.
- Avoid Git configuration writes during routine history retention and skip identical configuration values elsewhere.
- Retain automatic older v0.6 workspace upgrades, stable metadata identities, grouped checkpoint Resume, literal continue, and existing files/memory/timeline recovery.

## v0.6.73

- Automatically upgrade supported older v0.6 workspace schemas when opened. Schema 14 is the prior v0.6 format and is admitted for the additive schema-15 checkpoint migration. Separate the supported minimum from the current version so a future schema bump does not reject every older supported workspace.
- Preserve the old metadata version until the database upgrade succeeds. Repeat opening is idempotent. A workspace created by a newer application identifies that requirement correctly.
- Add actual prior-release workspace upgrade tests and native cold-start coverage. Preserve grouped resume, literal `continue`, and existing files, chats, memories, task state, attachments, checkpoints and Undo.

## v0.6.72

- Save a coordinated resume checkpoint after each completed model/tool group. A requested batch of tools creates one resume point at its final result; completed assistant responses create one at their final visible bubble.
- Show **State saved** only after a committed checkpoint passes validity checks. Right-click that exact bubble for **Resume from here**. Streaming, truncated, interrupted and unresolved tool groups cannot become resume points.
- Restore the selected group's conversation, owned project files/Git state, memories, task state and retained attachment links, then queue literal `continue` without resubmitting the original prompt or attachments. Preserve **Undo latest rewind** and all existing pre-user-prompt actions.
- Verify exact checkpoint content, including large objects and attachments. Cache unchanged content receipts; missing, changed or corrupt checkpoints block resume before changing the live project.
- Keep project ownership until checkpoint/restoration workers settle even when cancellation repeats. Managed background processes block checkpoint capture and resume while related project files may still change.

## v0.6.71

- Preserve the navigator marker window per user, workspace and chat across rebuilds, switches and reloads. After the down arrow, keep the newest markers visible as prompts append. Earlier-marker browsing remains independent of transcript follow.
- Preserve queued Latest intent between a refresh acknowledgement and its deferred jump so visibility, page-hide, chat-tab and periodic saves cannot restore it as paused reading.
- Cancel a deferred Latest jump when the user subsequently scrolls upward or selects another destination; clear the pending flag before loading the actual newest history window.


## v0.6.70

- Phone RETRY and UI run Retry send `continue` after a saved run stops. Keep the original prompt and attachments in history instead of submitting them as a new request. Preserve work, memories and unrelated drafts.
- Keep the selected model and Thinking choice. Continue through the normal queue, including known queued retries saved by a previous release. Reject started attempts whose original saved conversation is unavailable.
- Offer continuation codes in enabled stopped-run notifications as well as error alerts. Keep UI retries on the same progress / Running again / quiet-completion path as phone retries. Concurrent phone/UI actions reuse one queued continuation.
- Handle older history messages with absent metadata when building retry alerts. Requests cancelled before they ever started still start their saved request.
- Show continuation wording on the saved retry turn so its transcript matches the `continue` sent to the model.

## v0.6.69

- Show a bounded error reason in ntfy alerts, removing secret URLs, credentials, request bodies and paths. Offer exact-run RETRY/STATUS commands when the saved request can be retried.
- Requeue direct and queued failed prompts with original model, Thinking choice and copied attachments. Preserve saved files, memory and timeline; reject duplicate, expired, wrong-topic, locked, archived and changed-timeline replies. Clear only the explicitly retried run's failed backend hold.
- Report preparation, queueing and retry, then send Running again only after confirmed output. Keep recovered runs quiet through completion until another error; report bounded automatic GPU/memory recovery. Preserve normal completion preferences for other runs.
- Keep phone retry preparation process-owned and join it before timeline deletion. Report failures before model admission, and keep notification faults from interrupting work.

## v0.6.68

- Save follow mode as a user choice, independent of the temporary gap before a redraw or streaming bottom pin. Switching tabs no longer restores that gap as paused reading.
- Persist Jump to latest immediately, including during initial restoration and pending history loads. Save actual reader positions before chat-tab navigation and browser visibility/page-hide transitions.
- Restore an explicitly paused reader as paused, and resume a pending bottom pin when the browser page becomes visible. Remove the prior controller’s lifecycle listeners on rebind.
- Retain v0.6.67 navigator rectangles, arrows, larger grey squares and unchanged purple squares, plus prompt deletion and Undo.

## v0.6.67

- Replace the visible prompt-marker scrollbar with grey rectangles for earlier/later hidden markers. Each click reveals another page, and the rectangle disappears at its corresponding end. Preserve independent wheel, touch and keyboard scrolling without a visible scrollbar.
- Add a top arrow that jumps directly to the beginning of the chat and marker list. Keep the bottom arrow jumping to latest/follow mode and move the marker list to its end.
- Enlarge normal grey squares from 7 px to 10 px while retaining the purple event squares at 7–11 px, their 24 px click targets and existing event menus.
- Preserve every prompt, exact event target, same-chat refresh position, keyboard focus, resize behavior, Browse all and v0.6.66 prompt deletion/Undo.

## v0.6.66

- Add **Delete prompt & everything after** to the context menu of one saved user prompt, with a confirmation showing the exact removal boundary and saved-message count.
- Restore pre-prompt project files, memory, task state and attachments through the existing atomic rewind transaction; remove later conversation and bookmarks, and clear the discarded composer draft and scroll position. Retain **Undo latest rewind**, including the previous draft and scroll state.
- Stop and join this chat's generation, completion check and approval waits; cancel its queued prompts and in-flight retry preparation before restoring. Keep deletion process-owned across page reloads and block new same-chat writes while it runs.
- Clear only the deleted chat's settled runtime holds. Preserve other projects' active work and queue entries. Refuse locked chats and missing checkpoints, and identify recorded external mutations before confirmation.

## v0.6.65

- Keep every user prompt as a 7 px grey rounded square, including bookmarked and selected prompts. Preserve all prompt markers in long histories.
- Use separate purple rounded squares for selected events between prompts. Begin at 7 px and grow gradually with entry count, capped at 11 px; retain 24 px click targets.
- Move event icons and counts inside the pointed menu. Include each event's excerpt, timestamp, exact destination and a link to the related original prompt.
- Remove visible New badges and the obsolete prompt-group layout selector. Keep event filters, saved legacy preferences, exact-target selection and the bottom down arrow.

## v0.6.64

- Start downward context tuning from the estimated history actually assembled in the rejected request, within the selected context ceiling. Use small bounded reductions and allow up to 24 retries; remove the fifth-retry halving and jumps to an earlier known-good target.
- Reassess available capacity gradually on natural subsequent requests after stable acceptance. Back off after failed upward trials and bound trials per run.
- Distinguish whole-input estimates, estimated retained history, backend-reported input usage, configured limits and output reserves in recovery diagnostics.
- Retain a compact context-tuning ledger across detailed-log rotation and sessions, with explicit retention limits in diagnostic exports.
- Correct the earlier diagnostics interpretation: five interruption/retry incidents are visible, but only the final retained incident is confirmed as a memory-driven context adjustment.

## v0.6.63

- Replace inline group expansion with an anchored event list to the right of its marker. Show event labels, times, settings-filtered entries and explicit counts; retain the full prompt rail.
- Preserve exact destinations for each enabled context adjustment, error, recovery, stop and attention event. Deduplicate bookmarked events by their actual bubble.
- Retain browser-local inspected-event state per signed-in user and chat. Opening a chat or group does not clear New indicators; inspecting the actual event does.
- Show immediate navigation feedback, preserve the latest selected destination through initial restoration and history refreshes, and provide explicit recovery for delayed navigation.
- Clear a previous controller's active request and anchor when rebinding chat navigation, and retain increasing request IDs so a late acknowledgement cannot match a newer request.
- Distinguish active completion verification, continued work and resuming work in queue admission messages, the sidebar, queued prompt cards and the queue dialog.
- Derive waiting-slot labels from the blocking project's current lease. Preserve real durable queue positions and avoid inventing a queue position for a direct request still waiting outside slot admission.
- Mark the owner as continuing when a new user follow-up supersedes an in-flight completion verdict, before the next ordinary model call begins.
- Replace full-history reads in attachment/package request detection with a content-only query for the newest user message. Preserve tool availability and execution guards, timestamp ordering, rewinds and chat isolation.
- Retain same-model verification, queue ownership, retry budgets and automatic queue release after exhausted verification.

## v0.6.62

- Add an optional Completion Check navigator marker for each saved check, with its status and an exact link to the check bubble. Preserve existing indicator defaults and bookmark visibility without duplicate markers.
- Keep compact-group disclosure buttons stable during expansion, so clicking again closes the intended group.
- Retain the open group across redraws of the same chat while preserving outside-selection collapse and isolation between chats.
- Refresh navigator entries after saved activity changes and new prompts; normalize the render token used to reject stale callbacks.
- Prevent deferred density adjustments and initial saved-position restoration from undoing a newer marker selection or manual navigation.
- Preserve v0.6.61 completion verification and queue policies.

## v0.6.61

- After completion verification exhausts its available attempts, preserve an unconfirmed result and allow other eligible queued projects to proceed automatically. Continue holding the queue throughout checking and automatic continuation.
- Retry malformed decisions and recoverable verifier errors/timeouts up to three attempts per reply. A GPU failure during completion verification follows its existing one-retry recovery allowance, then hands off if completion remains unconfirmed.
- Preserve the unconfirmed notice, saved conversation, model and recovery actions across reloads. Continue and Retry use normal queue order after exhaustion, with duplicate-click protection.
- Release only the settled verification run’s own completion gate and matching finished backend-recovery hold. Preserve other owners, active retries and unrelated failure/restart handling.
- Identify released verification results in the queue panel without requiring Resume queue. Update settings and error text to explain the automatic handoff.

## v0.6.60

- Require completion verification with the active chat’s model before handing off an apparent final reply. Keep the check exchange inspectable in its timeline event.
- Count up to three decision attempts per reply, with a separate total check sequence. Renew automatic continuation after a successful distinct tool invocation; retain the two-resume guard when no new successful tool work occurs.
- Hold unrelated queued and already-waiting chats when completion remains unconfirmed. Persist the hold, identify its project in the queue, and allow that project to continue before other work. Explicit Stop remains authoritative.
- Separate current attempt, no-progress allowance and run totals in the completion card; label older saved events with their legacy count scope.
- Show the blocking completion owner for direct sends waiting in the sidebar and footer. Keep run updates available to a reloaded page while avoiding updates to the deleted original page.

## v0.6.59

- Give optional compact groups a distinct purple stacked marker with a count and disclosure arrow. Expand the group’s individual markers inline with an animated purple frame instead of opening a group picker. Keep the global Browse all search.
- Keep a group open when selecting its own prompt or bookmark. Collapse it when selecting outside the group, opening another group, or using Latest/Top. Preserve exact bubble destinations, bookmark gold and the selected marker’s teal accent.
- Support Right arrow to open and Left arrow/Escape to close; honor reduced-motion preferences. Retain open membership across ordinary navigator refreshes and resizing.
- Preserve individual markers as the default, existing navigator appearance settings and optional status badges. See the current verification report for measured checks and limitations.

## v0.6.58

- Restore individual prompt markers as the default, with an independently scrollable rail for long projects and a searchable Browse all control. Keep viewport-sized compact groups as an explicit layout choice.
- Add Settings → General → Prompt navigator controls for navigator visibility, marker layout, bookmarks and six optional status categories. Preserve the existing master visibility preference; default status badges to off.
- Keep each prompt marker or group count visible when indicators are enabled. Label historical errors as past events, and make filtering a display preference without changing saved history or in-chat approvals.
- Preserve exact bubble identity across virtualized history loading, including later bookmarked Thinking/reply segments. Defer mounted-target jumps during an in-flight history update so an older restoration cannot overwrite the selection; honor the latest navigation intent and highlight the selected bubble.
- Add focused settings and navigator regressions and isolated authenticated browser journeys. The current verification report records the completed checks, reproduced failures and limitations.

## v0.6.57

- Check every eligible nonempty tool-free final reply, including long replies, removing the former 800-character gate. Keep the existing enabled-by-default preference and rename it Check final replies.
- Require strict CONTINUE decisions to specify an existing unmet requirement and a concrete authorized next action. Use neutral wording against invented scope, repeated completed work and optional polish.
- Bound a submitted run to three check requests and two automatic continuations. Invalid checks consume the check budget; exhausted or inconclusive checks pause visibly, with full inspection details and accurate applied-continuation counts.
- Keep queued user steering authoritative over checker continuations, including late follow-up admission, and clear pending check state when Stop races with follow-up intake.
- Preserve the complete candidate reply in the control request, including pasted-text-looking literals; do not rewrite runner control messages as deferred user attachments.
- Retain the original objective and recent coherent assistant/tool blocks when the first oversized historical turn cannot fit as a whole. Preserve newer turns, final input budgeting, stable context epochs, saved history and the fresh-run context reset.
- Add privacy-safe completion-gate diagnostics and bounded history-selection reasons/counts. Include targeted protocol, runner, continuity and real authenticated browser journey coverage; see the current verification report for exact scope and limitations.

## v0.6.56

- Add metadata-based prompt navigator indicators for errors/denied tools, context resizing/compaction, stopped runs, backend recovery and attention; show pending approval on its original prompt.
- Compress long navigators into viewport-sized groups with counts, searchable exact entries, keyboard controls and retained bookmark targets. Keep group pickers usable during resizing and on narrow screens.
- Keep Ask approval requests with the running task for queued, retried, remote and direct runs. Show exact arguments, actual slot and Allow once/Deny/Stop controls across reload, project switching and signed-in clients.
- Validate fresh authentication and exact request/run ownership; reject stale controls and current Off permissions. Read authoritative saved settings when admitting a new direct run.
- Distinguish unavailable approval delivery from an explicit denial; preserve existing permission defaults.
- Label unstarted tools as waiting for approval instead of running, paint fast queued prompts on the first observer update, and close the queue dialog when navigating to the original prompt.

## v0.6.55

- Anchor run actions and queued retries to one original prompt, with clickable references and compact saved retry rows instead of repeated full prompt text. Preserve each attempt’s own edit/checkpoint identity.
- Use actual attachment cards in retry, replacement and run-queue views, retaining preview/download access to the files owned by each attempt.
- Clear clean precommit replacement cancellation; retain recovered drafts and cleanup errors after committed restoration.
- Track explicit Stop by task identity so a replaced live UI snapshot cannot mislabel it as an interruption.
- Keep cancelled/failed retry copies out of unrelated composer drafts; preserve normal new-request cancellation behavior.
- Make compact Events and cross-project queue prompt links work without swallowing clicks or using deleted UI parents.
- Keep the global queue dialog open after Cancel, Retry and Stop by attaching refreshed dialogs to the page instead of the closing dialog.
- Keep chat actions usable in narrow windows with a Projects drawer at 600 px and below, and wrap response metadata.

## v0.6.54

- Replace the fixed 12-hour login expiration with Settings → General → Login session timeout, defaulting to Never and offering timed durations.
- Apply changed time limits to valid active sessions while preserving existing WebSocket and account capabilities; keep expired/revoked sessions invalid.
- Let the server enforce session deadlines and refresh valid browser cookies without extending finite server deadlines. Manual logout, password/account changes and process restart still require sign-in.
- Fix narrow Settings layout under NiceGUI 3 so the compact section selector replaces the sidebar and leaves the preferences and Save/Cancel controls usable.

## v0.6.53

- Recognize the explicit Metal GPU-hang error and retry the unstarted model response once per run after a cancellable five-second delay, retaining the original agent/model slot and prior tool results.
- Pause persisted queued runs during recovery, including workers already waiting for a slot. Successful recovery clears only its own pause; failed, stopped or interrupted recovery persists until explicit Resume queue.
- Show the recovery attempt and paused queue state in the timeline and queue UI, with pending cancellation and manual resume available.
- Keep queue-dialog controls current across recovery transitions; retire off-screen completed-run spinners and notify before removing the clicked cancellation/resume controls.
- Close nested backend streams immediately when a retry is stopped; require a clean successful completion signal before releasing the recovery hold.

## v0.6.52

- Retire inline retry notices for queued prompts removed by Edit & replace timeline in the same transaction as the rewind. Keep original attempts in run queue history and leave unrelated or never-saved failed requests available.
- Hide historical retry notices while replacement waits/restores, and restore them if the rewind is cancelled or fails before committing. If sending fails after restoration, preserve the edited draft without resurrecting the superseded retry.
- Label remaining retry cards as previous runs and clarify that retrying the original request is optional.

## v0.6.51

- Close follow-up intake immediately on Stop and route a prompt sent during cancellation cleanup into a persisted fresh run, including its attachments. The new runner starts Auto context at its configured ceiling instead of joining the stopped run.
- Preserve that prompt through tab changes/reloads and distinguish cancellation of a predecessor from cancellation of the new queued worker.
- Keep normal in-run steering and automatic context recovery behavior unchanged; fresh backend limits still constrain the next request.

## v0.6.50

- Place current and queued sidebar status inside the existing selectable project button. Name, ID/access information and status share the same click, hover, keyboard-focus and selected surface. Keep the title width and compact idle rows; allow visible status to wrap where needed.
- Route status clicks to the project, with pending-request management still available through Run queue. Preserve in-place status updates, context menus, drag controls and project-files double-click behavior.
- Fix a lost-click race observed during the isolated browser walkthrough: run startup and completion no longer delete and recreate sidebar navigation buttons. Update busy status and first-prompt titles in place so an in-flight project click retains its native listener.
- Return HTTP 404 with no-store/nosniff headers for missing or unknown terminal browser assets, preventing JSON error responses from being treated as successful JavaScript. Existing asset responses are unchanged.
- Extend native-control regressions for passive status children and add missing-asset HTTP response coverage. Browser acceptance and final package results are recorded in the current verification report.

## v0.6.49

- Correct the timeline-replacement card alignment: separate its layout from right-aligned queued messages, keep the spinner beside its heading, and constrain the card to the chat column.
- Identify project-writer blockers by their live project/slot metadata. Do not present Auto as if it explained the current replacement wait; own queue/slot selection applies after restoration.
- Identify file-history saving while it retains the project writer, including after Stop. Preserve writer ownership until saving completes.
- Avoid describing cancelled completion checks as invalid model decisions.

## v0.6.48

- Add model-declared completion checks for nonempty tool-free final replies shorter than 800 visible characters, excluding reasoning. Strict JSON accepts only COMPLETE, CONTINUE, or NEEDS_INPUT with a question. HarnessyXO performs no semantic or keyword classification.
- Bound checks to two per submitted run without resetting after tools. Cap each check at 2,048 output tokens (or the profile's lower limit), five minutes, and 65,536 captured characters. Invalid/truncated replies never count as completion; no tool call from the check is executed.
- Show a running/finished completion-check bubble with a collapsed inspection view for the candidate, check prompt, raw model reply, and separate thinking. Keep control exchanges out of normal conversation and future model context; allow copying them from the bubble.
- Resume authorized work after CONTINUE, show the required question after NEEDS_INPUT, and pause with Continue guidance when completion is unconfirmed. Preserve Stop, writer/model-slot release, and queued user steering throughout checks.
- Add the enabled-by-default Check short final replies setting. Preserve the normal tool-schema prefix and model profile while applying request-local output caps across compatible backends and native Ollama.
- Refresh persisted activity updates for detached/reconnected views as well as the active page.

## v0.6.47

- Add compact sidebar status lines for actual running slots, PP, persisted queue positions/slot preferences and timeline-replacement writer/restoration waits. Preserve both active and pending work for the same chat.
- Derive occupied slots from live scheduler leases, including temporary subagents, instead of stale live-state or legacy queue-lane fields. Keep pre-queue replacements unassigned and distinguish direct live wait positions from persisted queue positions.
- Refresh status controls, workspace queue counts and busy-dependent menu actions in place. Preserve sidebar selection and mounted menus through ordinary slot, phase and queue transitions.
- Add lifecycle regression coverage for replacement admission/cancellation/failure, reload, tab/workspace switching, queue renumbering, active-plus-pending work and delegated slots. Repair an outdated fixed handover filename assertion to follow the current release.

## v0.6.46

- Halve automatic clipboard text-to-file conversion from 32,000 to 16,000 JavaScript string-length units per paste, including exactly 16,000. Preserve the full pasted text in the existing private attachment flow.
- Keep attachment delivery, history retrieval and context-budget behavior unchanged. Update the existing source guard and document the character/token distinction and composer-editing implications.

## v0.6.45

- Add **Try again** to stopped/failed/interrupted chat notices, including saved prompts, and recent queue history. Cancelled pending jobs can also be retried from history. Refresh an open queue dialog after its Stop action finishes.
- Append a new attempt with the original prompt, profile, thinking and available slot preference. Preserve current project files/history, composer text and pending attachments; use private attachment copies for the retry.
- Persist a unique retry-to-source link so duplicate clicks and separate pages/processes cannot enqueue the same retry twice. Retried predecessors leave the retry list; unsuccessful child attempts remain retryable.
- Copy attachments off the UI loop with rollback on failed admission. Browser callback cancellation does not abandon preparation. Orderly shutdown finishes preparation with queue admission stopped, preserving the committed job for the next launch.
- Explain unavailable attachments/profiles, blocked projects and slot fallback without silently dropping request inputs.

## v0.6.44

- Fix ghost startup cards for saved queued prompts outside the bounded transcript window. Check durable history by queue job ID instead of whether the User bubble is currently rendered.
- Retire startup cards on the existing UI timer when the checkpoint completes, even though the queue row remains running and a transcript refresh is deferred. Stop checkpoint polling once that card is retired.
- Add a job-specific **Stop run** action to genuine startup cards. Retain pending removal and unsaved terminal notices, and reject late Stop clicks for a completed or different run.

## v0.6.43

- Move the project-writer wait and historical restoration into a process-owned background job. Edit & replace timeline now closes on confirmation, before either writer-lock or agent-slot waits.
- Show progress and Cancel above the composer, outside transcript scrolling. Identify the blocking project, reconstruct the card after navigation/reload, and preserve other projects' drafts. Block additional sends into the project while its timeline is changing.
- Keep the writer lease through cancellation of the restoration thread. Discard only uncommitted staged uploads; if restoration already committed, preserve the edited draft and cancel its send. Ignore duplicate confirmation events and route a late dialog Cancel to the correct operation.
- Keep the existing persistent queue handoff after restoration and cancel background replacements during orderly application shutdown.

## v0.6.42

- Hand edited timelines to the persistent global run queue after restoration. Finish the dialog callback before waiting for agent capacity, preserving the exact edited prompt, attachment selection, model and thinking setting.
- Show the existing queued prompt card and removal control after replacement. Pending work survives tab changes and page reloads without keeping the dialog's send callback alive.
- Share attachment reservation/rollback with ordinary queued sends. Keep a failed enqueue as a draft in the original project, and prevent a failed redraw after successful enqueue from creating a duplicate draft.

## v0.6.41

- Highlight the owning project whenever a project-owned tab is selected, including Project Files and individual files opened from that panel. Reuse each tab's existing workspace/project identity instead of restricting sidebar selection to chat tabs.
- Apply the same selection when closing the active tab or restoring an open session. Workspace-wide tools retain workspace-only selection.

## v0.6.40

- Add a visible **Auto cap** to the bottom status bar, with exact tokens and the selected ceiling in a hover/focus tooltip. The value follows actual request snapshots as automatic tuning reduces or raises retained history.
- Publish request-budget snapshots to both foreground and queued/remote live state. Record the selected runtime-bounded ceiling and larger-trial flag in request metrics; expose the ceiling in Performance details.
- Show **Last auto cap** for historical requests and **Auto cap pending** for a new run awaiting its own request. Keep values scoped to the selected model/profile. Status ticks require no additional database reads or transcript scans.

## v0.6.39

- Fix the diagnosed `prefill_memory_exceeded` → HTTP 507 / null-code `metalcap` model-load failure sequence. Recognize the narrow model admission error, retain its raw payload, and retry after 2/5/10/20/30 seconds without consuming the eight context-reduction attempts.
- Keep model-load projected/current/model/ceiling values separate from prefill-memory samples. Resume downward tuning when the backend evaluates and rejects the prompt; report persistent load pressure separately.
- Remove hard request rejection based solely on approximate UTF-8 token counts. Continue history compaction, preserve mandatory input, and defer acceptance to the actual backend. After a real rejection with no remaining removable history, stop without replaying identical requests.
- Distinguish waiting, backend blocking and recovery in the activity card; replace stale error reasons and memory figures. Cancellation during a wait remains immediate, and generated output still prevents automatic replay.

## v0.6.38

- Add model and thinking selectors to Edit & replace timeline. Keep selections local to the dialog until restoration succeeds; Cancel and failed restoration preserve current chat settings. Reject missing models, unsupported thinking choices and known image/model incompatibility before rewinding.
- Add compact information tooltips to input, Thinking, reply and Tool bubbles, including collapsed Thinking/Tool headers. Preserve existing copy, bookmark and timing controls.
- Save credential-free model/profile/thinking snapshots on user inputs, queued follow-ups, assistant output and tool results. Carry the same settings through live and detached rendering, background jobs and terminal error/cancellation records. Profile edits never rewrite historical labels; legacy missing fields remain unknown.

## v0.6.37

- Replace separate OS creation buttons with one searchable VM catalog, per-OS resource defaults and relevant installation fields. Add Debian 13, Fedora 44, Ubuntu 26.04, Kali 2026.2 and OpenWrt 25.12.5 alongside existing Ubuntu 24.04 and Windows 11 targets.
- Use pinned official Kali/OpenWrt images with checksum verification. Add a rootless QEMU OpenWrt controller with an expanded ext4 disk, ash shell, private LAN/WAN NAT, localhost LuCI access and complete cold snapshots. Keep test guests independent of the working VM.
- Replace the maximized targets dialog with a compact toolbar, search/type filters, empty states and expandable details. Dispose of target status timers when their UI closes or rebuilds.
- Improve narrow-window Settings navigation, dialog/form scrolling, long labels, model profile controls, workspace-picker headers, icon accessibility, keyboard sidebar disclosure and reduced-motion transitions.
- Verify real native control events and real ARM64 image preparation. Full VM boots and Chromium layout checks remain unavailable in this build runtime; record those limits explicitly.

## v0.6.36

- Add target-environment discovery to normal coding chat: distinguish build/run targets from the HarnessyXO host and working VM, inspect accessible targets directly, or request a focused read-only command report that the user can paste into chat. Apply this only to writing/modifying/debugging code where missing target details materially affect implementation or validation.
- Instruct the agent to wait for needed target facts before dependent implementation, use official evidence matching installed versions, check unexpected option/API errors before speculative retries, and retain target-specific source/date findings. Preserve ordinary work without unnecessary questionnaires; the interview remains unchanged.
- Return UTC retrieval timestamps from web search/open and retain them in cached Find results. Older cache entries have an unknown date; fetching a page is not proof of its accuracy or publication date.

## v0.6.35

- Add an explicit default model for new projects/chats and default thinking per model. Keep the profile editor selection independent; apply model defaults to new chats and model switches, preserving existing saved chat choices.
- Open Project Files by double-clicking a sidebar project/chat, including when the first click rebuilds the sidebar. Retain single-click chat navigation.
- Rename External Targets to External/Test Targets and add independent Ubuntu 24.04 / Windows 11 test VMs, with internet access for updates and software installation. Keep host credentials and VM state outside model-visible project files.
- Add Bash/PowerShell command and binary file bridges, interactive shell, optional localhost VNC desktop, asynchronous start/stop controls and complete cold snapshots including TPM/firmware state. Preserve the existing external-device access policy.
- Use QEMU through Lima; Windows is experimental and requires Lima 2.2+, swtpm and a matching English (United States) ISO. Expose architecture/resources, progress and actionable prerequisite errors.
- Verify real NiceGUI creation/default controls and browser double-click behavior, plus target migration, file transfer, lifecycle and permission regressions. Full guest boot validation remains required on the user's host.

## v0.6.34

- Recheck transient exit-75 VM file receipts after applied Project file edits without replaying the edit. Confirm the host still has the written bytes, then require a stable matching VM hash. Stop if another writer changed the host file, the views genuinely disagree, or four read-only attempts remain inconclusive.
- Account for the uploaded 3h46m `replace_in_file` failure: the host write completed but the VM check produced no digest, so the previous stop could not establish whether the bytes diverged. Record the bounded read attempts without logging file content or paths.

## v0.6.33

- Continue polling oMLX activity for a request ID safely bound before two same-endpoint requests overlap. Keep its own prefill/decode counters and watchdog progress after the other job stops, without attributing another job's model-wide counters to it.
- Reproduce the uploaded diagnostics: the surviving request remained backend-active and request-scoped during repeated health checks, but v0.6.32 stopped its activity poller at overlap and terminated it at 600 seconds without new progress evidence. Keep the hard limit for a truly static request, record bounded request-scoped numeric progress for future diagnosis, and accurately describe backend-active stalls in the UI.

## v0.6.32

- Open Project/Chat tabs from one sidebar click and synchronize sidebar highlights with the active chat tab, including across workspaces, restored sessions, and tab close fallback. Workspace rows open Environment only after a double click.
- Suppress backend-wide oMLX and Ollama live progress counters for overlapping requests to the same endpoint. Clear previously displayed counters when overlap begins; keep per-request stream updates and authoritative final usage. Refuse to choose between oMLX prefill and generation rows for different requests.
- Start password SSH with a private executable launcher created per request, so extracted `ssh_askpass.py` need only be readable. Verify real broker execution against an SSH stand-in after removing the helper's executable bit.

## v0.6.31

- Allow explicitly configured root SSH targets, including a dedicated `/root/<subdirectory>` test root. Retain protected system path checks and clarify in the UI and model tool descriptions that command filtering does not remove root privileges or confine symlinks.
- Add password authentication beside the existing identity-file/SSH-agent option. Save passwords in a private host-only settings file, never in the workspace database or model tools; send one password to OpenSSH using a private temporary named pipe and `SSH_ASKPASS` without adding it to process arguments or the environment. Keep and rotate existing passwords on edits, and erase them when switching to key mode or removing a target.
- Upgrade existing target tables in place with a `key` authentication default; test root validation, private credential lifecycle, rejection of unsafe files, and fake-OpenSSH connection, execution and binary copy paths.

## v0.6.30

- Stop encouraging automatic `attach_file` calls for files already available in the canonical Project folder. Instruct the agent to report exact `Files/Project-<ID>/relative/path` locations and let users open/download the original in Project Files.
- Hide and block the chat attachment tool unless the latest User message explicitly requests a separate attachment or direct single-file download. Preserve explicit snapshots without changing existing files or older attachments. Add focused tests for allowed/blocked requests and the actual file snapshot.
- Clarify that “Generating next action” is a waiting indicator when no new visible text/tool detail has arrived; a recently refreshed call-wide tokens/second figure can still be shown during backend tool-call assembly. The UI streaming behavior is unchanged.

## v0.6.29

- Color the tab families separately, including chat, environment, file explorer/editor, terminal, memory, downloads and file history, with matching active accents and dark-theme surfaces.
- Separate sidebar selection from tab activation. A single click highlights a workspace or chat without opening a tab, a double click opens it, and tab switches do not move the sidebar selection. Keep workspace rows mounted during the first click so browser double-click events survive; restore chat selection with the UI session.
- Group app, workspace, chat and file context-menu actions with separators, including conditional read-only/archive variants. Keep attachment and follow-up callbacks scoped to the active tab's workspace when it differs from the sidebar workspace.

## v0.6.28

- Show each persisted queued prompt, attachment name, position and selected slot in its own chat after sending, tab switching or page recreation. Retire the temporary queue preview only when the runner's matching saved User prompt is visible; leave a dismissible copy if a failed start never saved a prompt. No duplicate request or model context is created while waiting.
- Add Auto and explicit Slot 1…N choices to the queue send menu with more than one Global Agent Slot. Store the preference separately from legacy queue lanes so v0.6.27 jobs remain Auto. A pinned job waits for its chosen slot without blocking safe Auto work in another free slot.
- Apply changed slot limits to waiting workers, and return pending jobs targeting a removed slot to Auto. Keep the single global queue, project dependency exclusions, one-slot delegation transfer and backend inference concurrency boundaries.
- Update old run-queue regressions to the actual v0.6 global scheduler and cover persistence, visible text across tabs/reloads, slot admission, legacy migration, attachment ownership and checkpoint handoff.

## v0.6.27

- Fix a live v0.6.26 recovery skip: the backend reported a recognized mid-prefill memory abort after one 250-character reasoning delta, and the oMLX adapter's exact synthetic-notice wrapper check allowed the delta to count as generated output. Confirm the complete abort detail while accepting known wrapper variations caused by the reasoning/tool-call stream.
- Add transport/runner regressions for the missing closing bracket, missing opening bracket, and unbracketed `Error:` notice forms, while retaining tests that prevent replay of real reasoning, answers, tool calls, or unconfirmed lookalike text.
- Record privacy-safe numeric diagnostics when a prefill abort notice fails confirmation, so a future unmatched stream can be diagnosed without exporting the model's reasoning text.

## v0.6.26

- Apply automatic down/up tuning to Custom, presets, Maximum, and legacy ceilings as well as Auto. Never probe above the selected/runtime ceiling or overwrite saved values. Explain automatic adjustment beside the Custom GUI field.
- Reproduce and fix the oMLX stream sequence that emitted a synthetic abort notice before the structured memory error. Hold only a bounded potential notice; suppress it only when the following error confirms its exact text. Flush unconfirmed text unchanged and preserve the no-replay guard for real model/tool output.
- Correct premature prefill stalls seen twice in supplied diagnostics: a missing entry in oMLX's best-effort activity dashboard is unknown, not proof of abandonment. Recognize waiting/other activity phases and retain the shared 600-second prefill silence limit.
- Give arriving HTTP-200 protocol errors priority over watchdog deadlines. An inferred stall can no longer replace a backend error already received in the current queue item.
- Record privacy-safe health-check decisions and capacity-recovery skip reasons. Preserve all earlier startup, bookmark, context, and VM-observation corrections.

## v0.6.25

- Replace Auto's half-window/96K heuristic with the configured/observed window, still bounded by request overhead, output reserve, safety, and actual runtime capacity. Rename the UI choice from Auto / Balanced to Auto and explain the adaptive behavior.
- Move tuning calculations into a provider-neutral module. Prefer reported token limits or predicted/allowed memory; use two comparable memory observations to estimate the fixed/variable allocation. Without usable quantitative feedback, take four small reductions, halve on retry five, then resume small reductions within eight retries.
- Track actual accepted/rejected history sizes for Auto. Probe upward on later natural requests, recover downward after rejection, stop at token granularity or eight upward probes, and restore eligible saved history for a larger trial. Keep profile/backend settings unchanged; reset learned state for a new job or explicit retained-policy change.
- Preserve error bodies through generic OpenAI-compatible HTTP/SSE/JSON and native Ollama HTTP/NDJSON paths. Normalize explicit context-length errors, including llama.cpp's reported prompt/context counts, into shared capacity recovery. Keep partial-output replay disabled and unrelated/model-load failures explicit.
- Finalize interrupted trial Events even when failure occurs before transport. Record calculation methods in diagnostics without prompt contents.
- Clarify that mount lifetime flags are capabilities, not VM lifecycle events, and backend failures do not establish a VM restart or its cause. No VM lifecycle behavior is changed.
- Preserve the complete v0.6.22 startup/audit, v0.6.23 bookmark, and v0.6.24 abort-recognition fixes. Existing settings/workspaces remain compatible.

## v0.6.24

- Normalize oMLX's structured `prefill_memory_aborted` errors into the existing `prefill_memory_exceeded` recovery condition. The eight-retry feature was present, but the distinct mid-prefill abort code bypassed it.
- Recognize the explicit mid-prefill memory-guard abort wording when older streaming error objects omit the structured code. Preserve original provider fields, status, and numeric memory limits for diagnostics; do not guess predicted memory use from rounded prose.
- Keep eight progressively smaller run-local context retries, 1,024-token granularity, the single tuning Event, and advisory Custom values. Neither the saved profile nor backend memory limits are changed automatically.
- Do not replay a failing model request after it has delivered reasoning, answer text, or tool-call fragments, even if the backend labels its later failure as a prefill-memory error.
- Exercise structured HTTP and HTTP-200/SSE errors through the real client transport and runner retry loop, including success on retry eight, exhaustion, unchanged saved transcript/profile, and exclusion of unrelated errors.
- Retain the v0.6.22 startup/audit fixes and v0.6.23 immediate live bookmark correction. Existing v0.6 workspaces remain compatible.

## v0.6.23

- Fix recently completed live Thinking, reply, and Tool bubbles retaining their unsaved bookmark flag. Promote their existing UI elements at each persistence event, without waiting for the twelve-event transcript compaction or end of the agent run.
- Assign exact navigator anchors immediately. Bind later alternating Thinking/reply segments to the actual stored assistant message plus their segment kind, rather than a display-only message ID.
- Preserve live element and selection identities, existing bookmarks, bounded transcript rendering, and all v0.6.22 startup and audit fixes. Existing v0.6 workspaces remain compatible.
- Add regressions through the production send/completion callbacks for live eligibility, successful and failed tools, independent alternating segments, add/remove, and persistence through redraw/reopen.

## v0.6.22

- Fix new-project startup silently hashing every byte in References and then saving a whole-library snapshot before the first model request. Use conservative filesystem observations for upstream change detection; keep exact owned-project checkpointing and archive verification separate.
- Display checkpoint, upstream-check, and model-request preparation phases, with privacy-safe startup timing and recognised SQLite failure labels in diagnostics. Preserve exact historical reference versions already saved; startup no longer creates whole-References snapshots.
- Verify that a reused Git index represents the requested previous checkpoint before returning its commit. This prevents pre-prompt history from restoring stale bytes after a post-run revision refreshed the shared index.
- Release project mutation ownership when finalization setup fails or a background finalizer is cancelled before entry. Survive repeated cancellation at checkpoint/inline-history boundaries, and reap isolated history workers even when cancellation arrives during process creation.
- Refuse File History replacement when its safety snapshot cannot restore the current files.
- Scope model process access and browser sessions to the owning Project/Chat. Read-only Project Access does not permit polling, controlling, or stopping another project's process.
- Preserve competing files when exclusive attachment-copy creation loses a race on filesystems without hardlink support.
- Parse scalar instruction-interview list fields as whole strings and ignore malformed object/number fields.
- Rewrite WHY_HARNESSYXO around canonical files, managed environments, explicit project relationships, coordinated rewind, portability, goal interviews, and long-run operation. Remove development chronology and distinguish shipped environments from future targets.
- Existing v0.6 workspaces remain compatible at schema 14; no workspace recreation, VM rebuild, or model-setting change is required.

## v0.6.21

- Add right-click **Bookmark** and **Remove bookmark** actions for every saved User, Thinking, HarnessyXO reply, Tool, and event bubble.
- Extend the prompt navigator with gold diamond bookmark markers while retaining rounded-square prompt markers, compact centered spacing, explicit-target selection, and the mutually exclusive follow-bottom triangle. A bookmarked User prompt transforms its existing marker instead of duplicating it.
- Jump to the exact bookmarked bubble, including separate Thinking/reply surfaces and later alternating assistant-output segments. Bookmarks outside the mounted transcript use the existing bounded locate transaction with the real source message ID.
- Persist bookmarks as project presentation state outside model context. Message deletion cascades them, timeline replacement drops abandoned bookmarks, Undo restores them with the abandoned transcript, and sealed archive snapshots include them.
- Split terminal model output from exact post-run history publication in the browser lifecycle. The final answer now releases **Stop** immediately while a tracked lower-priority worker completes the file/memory revision under the same project mutation lease.
- Isolate post-run filesystem scanning, hashing, and Git work in a child Python process so it cannot monopolize the WebUI interpreter. Cancel that worker process group during application shutdown instead of making Ctrl+C await a multi-minute external-disk checkpoint.
- Show one durable **Saving project history** Event only after a five-second threshold, update it in place to success or red failure, and keep fast finalization silent. A related prompt waits for the revision before taking a global model slot; unrelated projects remain schedulable.
- Replace the finalizer's full-transcript load with one indexed message-head lookup. Headless/queued runs wait for the same isolated finalizer before reporting completion.
- Keep workspace schema 14 through an additive compatible table, settings schema 14, and backend-neutral inference behavior.

## v0.6.20

- Replace the historical checkpoint's one-Git-pathspec-per-file staging with one compact tree walk plus exact exclusions for large/special paths and nested repository metadata. Nested repositories remain byte-restorable rather than becoming gitlinks.
- Reuse the previous shadow commit when a persistent index and independent scanned path set prove the ordinary working tree is unchanged. Changed, added, deleted, mode-changed, and symlink paths still create a new exact checkpoint.
- Allow immutable large/project-Git objects to survive move/remount metadata changes only after bounded sampling and a complete byte-for-byte comparison both agree; changed bytes always create a new object.
- Add privacy-safe per-stage checkpoint timing diagnostics so future storage bottlenecks can be distinguished without exposing filenames, paths, prompt text, or file contents.
- Clear accepted pasted/file attachment chips from the live composer through process-owned run state, including after a browser reattaches during a long run.
- Add and release-gate `WHY_HARNESSYXO.md`: the creator's original ChatGPT-like local-model/project workflow, reasons behind nine development decisions, and sourced comparisons with OpenCode, Pi, Aider, Cline, Continue, OpenHands, Open WebUI's ecosystem, and AnythingLLM. Distinguish demonstrated behavior from workflow-fit judgments and unmeasured superiority claims; maintain this document each release.
- Keep only the current release's verification report in release trees; historical verification detail is summarized durably by this changelog instead of accumulating top-level validation files.
- Retain only the newest ten handover records and remove superseded top-level audit documents, keeping release Markdown focused on the living core documents and current evidence.
- Retain one checkpoint per accepted User prompt, timeline replacement/undo semantics, workspace schema 14, settings schema 14, and backend-neutral operation.

## v0.6.19

- Extend explicit Project Access from live files/saved history/linked attachments to the source Project/Chat's live model-visible memory and Current Task State, all read-only and immediately revocable.
- Keep shared state retrieval-first: source memory and task-state contents are never bulk-injected into the destination prompt. Existing tools accept `source_project_id`, and memory search covers both ancestors and direct Project Access sources.
- Label shared state as volatile, source-owned secondary project context—not inherited instructions, `Files/References`, vendor/user material, or vendor truth—and advise copying only source-labelled dependencies that the destination must preserve.
- Update Project Access UI descriptions and sidebar hover details without changing direct/non-transitive grants, file mounts, attachment privacy, workspace schema 14, settings schema 14, or backend-neutral behavior.

## v0.6.18

- Add an explicit model-facing boundary between `Files/References` and every HarnessyXO `Project-<ID>` working/artifact tree.
- Classify Project Access files as secondary work from a separate Project / Chat entity, not vendor/user-provided material or vendor truth by default. A request to consult them “for reference” changes relevance only, not provenance or authority.
- Reinforce the same rule in run prompts and file/access/history Tool results, including per-path provenance for reads, fingerprints, and text searches. Read-only remains a permission label only; workspace and settings schemas remain 14.

## v0.6.17

- Add a compact green **Read: XXXX, YYYY +n** badge beside a project's own sidebar ID whenever that project has direct external Project Access.
- Keep two source IDs visible in the row, summarize further sources with `+n`, and expose the complete read-only source list with project titles and IDs in hover details.
- Leave ordinary and archived project rows unchanged when no live direct grant exists, and fetch all active sidebar grant labels in one grouped query. Workspace and settings schemas remain 14.

## v0.6.16

- Add right-click **Project Access…** with checkboxes for explicit, direct, read-only sharing between active Projects / Chats. Checked sources expose live canonical files, bounded source-labelled saved-history retrieval, and only attachments linked from saved history; unsent drafts remain private.
- Keep Project Access independent from parenthood and non-transitive. Children do not inherit grants, and parent transcripts remain private unless explicitly selected.
- Project checked file sources into both structured tools and persistent VM namespaces as read-only paths, include them in namespace signatures and probes, show them in Project Files, and automatically rebuild only the affected project view when access changes.
- Add **Make child of…** and **Unchild** actions for existing projects. Reparenting changes one incoming dependency edge and moves the intact descendant subtree without relocating or copying canonical files, chats, memory, IDs, or descendants.
- Extend run serialization across direct Project Access sources, reject hierarchy cycles and unsafe/locked/running moves, retain pin anchors, and revoke live grants when a project is permanently archived while recording them in its sealed snapshot.
- Add `list_project_access` plus explicit source routing for chat history and linked attachments, including deliberate shared historical-image reactivation. Workspace schema and settings schema remain 14; behavior is independent of oMLX or any other inference backend.

## v0.6.15

- Change the new-install controller bind default from `127.0.0.1:6767` to `0.0.0.0:6767`, making authenticated HarnessyXO reachable from a trusted LAN without a local-only first configuration step.
- Advance settings schema to 14 and migrate only the exact former factory endpoint. Preserve customized bind addresses/ports and preserve an explicit schema-14 choice to return to localhost-only access.
- Update Server / Network defaults and guidance while retaining mandatory username/password login, same-origin mutation checks, authenticated API/Socket.IO access, LAN URL discovery, and explicit plain-HTTP/public-internet warnings.
- Retain v0.6.14's DGX/shared-Linux startup fixes and all v0.6.13 child-project namespace corrections. Workspace schema remains 14; inference backend behavior is unchanged.

## v0.6.14

- Fix first launch on shared-umask Linux hosts such as DGX Spark: create `.settings` as `0700` and safely tighten an existing same-owner directory which was previously created as group-writable `0775`.
- Repair permissions through a non-following directory descriptor. Never chmod a wrong-owner path or final-component symlink, and validate the credential root before `MachineStore` reads or creates application state.
- Put the already-verified or newly installed release-local `.vendor` directory on the launcher import path before its optional host-prerequisite pre-check, removing the false `No module named 'httpx'` warning.
- Retain v0.6.13's child-parent namespace correction. Workspace schema remains 14 and settings schema remains 13; inference backend behavior is unchanged.

## v0.6.13

- Fix the deterministic child-project failure left in v0.6.12: retained-view validation now enters both the keeper's mount namespace and PID namespace, matching command execution and giving `mountpoint(1)` the correct keeper-owned `/proc/self/mountinfo`.
- Stop falsely classifying a successfully mounted, nested same-filesystem parent bind as `ANCESTOR_MISSING`; a fresh child can establish its live read-only parent projection while the VM stays running.
- Bump the retained-view signature so a v0.6.12 keeper is invalidated and rebuilt automatically on first Tool use after the application upgrade.
- Include the allowlisted probe-stage code alongside the controller projection code in `run_command`, Git, workspace-mapping receipts, logs, and privacy-safe diagnostics. User command text, output, and paths remain redacted.
- Retain v0.6.12's bounded pre-execution repair and fail-closed behavior. Workspace schema remains 14 and settings schema remains 13; the fix is inference-backend independent.

## v0.6.12

- Add bounded pre-execution repair intended to let a newly created child Project / Chat establish its live parent/ancestor VM projection without requiring the user to stop or restart the workspace VM. Its validator entered only the mount namespace, so nested parent binds could still be rejected deterministically; v0.6.13 corrects that defect.
- Replace the single post-start namespace check with up to three bounded rebuild attempts and four short validation polls per attempt, all before the model-requested command is allowed to execute.
- Continue to validate the owned project mount, References, every nested ancestor mount, hidden Files/worktree backing roots, keeper identity, and signature on each attempt.
- Preserve fail-closed behavior after bounded exhaustion and add stage-specific probe diagnostics so a persistent failure identifies the missing or exposed mount class.
- Keep different-byte mapping/file observations immediately terminal, preserve project-persistent mounts after a successful validation, and remain independent of the inference backend. Workspace schema remains 14 and settings schema remains 13.

## v0.6.11

- Persist the exact unsent composer text independently for every Project / Chat instead of losing it when the mounted tab panel is rebuilt.
- Restore each chat's own draft after switching between chat or tool tabs and after recreating/refreshing the browser page. Draft text remains private UI state and is not inserted into the transcript or model context.
- Clear the persisted draft only after a successful normal send, queued follow-up, global run-queue submission, or explicit **Discard and close** action. Validation failures keep the text.
- Warn before closing a chat tab that still contains an unsent message, with separate **Keep editing** and **Discard and close** choices.
- Remove composer-draft rows when a Project / Chat or archived family is permanently deleted. Keep the implementation backend-neutral and retain workspace schema 14/settings schema 13.

## v0.6.10

- Make **Retained live context** hot-adjustable for active interactive, queued, and remote jobs. A saved change is adopted before the next model request or adaptive prefill-memory retry; an already-prefilling/generating request is never interrupted.
- Hot-load only `active_context_mode` and `active_context_tokens`. Model identity, endpoint, credentials, sampling, Thinking, output limits, and all other profile fields remain fixed to the run-start snapshot.
- Rebuild one cache-stable context epoch from the complete persisted transcript when the retained target changes, allowing a lower target to compact and a higher target to restore eligible history without changing durable chat, memory, task state, attachments, or Project Files.
- Replace the one-shot 96K/25% prefill-memory fallback with up to eight progressively smaller run-local targets. Use 1,024-token granularity, scale the decrement from reported memory overage when available, and start from the history actually assembled rather than an unused larger profile ceiling.
- Keep one amber tuning card updated across attempts. On success, show the accepted target and a suggested saved Custom value with additional headroom; on exhaustion, keep the target history and failure red.
- Keep automatic tuning advisory and run-local: it never overwrites the saved profile. Retain a backend-neutral implementation which activates only for the exact normalized `prefill_memory_exceeded` condition.
- Add an indigo **Live context setting applied** event and a Settings confirmation explaining that active runs adopt the change at the next safe request boundary. Workspace schema remains 14.

## v0.6.9

- Retry only inconclusive nonzero workspace-mapping probe executions against the same fsynced nonce, using four bounded attempts with 1.1 seconds of total backoff to absorb brief host-to-isolated-view visibility lag.
- Keep zero-exit different-nonce observations, exact whole-file digest mismatches, structured projection failures, and probe timeouts terminal; none of these safety-significant outcomes are retried.
- Record probe attempts, transient failure count, and successful recovery in verification receipts and diagnostics while continuing to remove the temporary probe before model-requested commands run.
- Let `copy_attachment_to_project` continue through its independent SHA-256/byte-count verification after a transient mapping probe recovers, without changing its non-overwrite or private-original guarantees.
- Render terminal workspace-safety responses with a red **Blocked after …** duration instead of the misleading green **Completed in …** label.
- Keep the recovery mechanism in the backend-neutral workspace layer. No behavior depends on a particular local model server or inference provider, and workspace schema remains 14.

## v0.6.8

- Add **Add replacement attachment** to **Edit & replace timeline**, allowing one historical User prompt to drop selected original files and include corrected or additional uploads before regeneration.
- Keep replacement uploads private under a dialog-token-owned staging status so they are invisible to ordinary composer sends and cannot be claimed by a different edit dialog.
- Revalidate staged file ownership, private-path confinement, regular-file type, registered size, and stable filesystem identity both before history materialization and inside the immediate rewind transaction.
- Atomically promote only the explicitly selected original and staged attachment IDs to the replacement prompt's pending set.
- Clean still-staged files on explicit removal, dialog cancellation, cancellation during upload, upload failure, or rewind failure. Token-scoped cleanup becomes a no-op once a successful rewind promotes a file, protecting commit/cancel races.
- Exclude newly introduced replacement uploads from the rewind recovery manifest so **Undo latest rewind** restores the exact pre-dialog attachment registry.
- Retain v0.6.7 bounded attachment retrieval, compacted-result recovery, and explicit attachment-to-Project copying without changing workspace schema 14.

## v0.6.7

- Bound `search_attachment` to 24,000 returned content characters in total, with four 4,000-character chunks by default. Historical 12 × 12,000 calls remain accepted but are deterministically clamped.
- Stop returning beginning/evenly-spread attachment samples after a lexical miss. A no-match result is empty and tells the model to refine its exact phrase, symbol, filename, identifier, or error-code query.
- Reduce `read_attachment` to one exact range capped at 32,000 characters. Older calls requesting 200,000 characters are clamped and report the requested/effective limits.
- Preserve attachment ID/query/range/count recovery coordinates when a retrieval Tool result is compacted, and explicitly distinguish compacting a result from retaining the original attachment.
- Include bounded `search_attachment` results in evidence-driven repeated-retrieval retention, preventing unnecessary re-fetch loops without permanently pinning large content.
- Add `copy_attachment_to_project` for deliberate byte-exact import into the current owned Project directory when grep, parser, or VM analysis is materially more efficient. The tool requires attachment plus filesystem-write permission, never overwrites, and never exposes the private backing path.
- Verify imported bytes before and after copying, reject changed or missing sources and path escapes, clean partial/cancelled copies, preserve the private original, and return SHA-256 plus normal host/VM file-view receipts.
- Record attachment retrieval metrics for ordinary uploaded text files as well as auto-created pasted-text attachments. Workspace schema remains 14.

## v0.6.6

- Add one provider-neutral stream-progress watchdog across generic OpenAI-compatible, oMLX, Ollama, and llama.cpp transports. It distinguishes raw connection activity from reasoning/answer/Tool/runtime progress.
- After 30 seconds without inference progress, perform a read-only backend health check and update live status without cancelling or retrying. Retain a 600-second initial prefill/model-start allowance and a 120-second post-output silence ceiling.
- Correlate oMLX prefill and generation activity by exact request ID. Only two confirmed request-ID absences may end the wait early; generic endpoint reachability never pretends to prove request liveness.
- Preserve partial Thinking and answer text before a stalled stream becomes a terminal error, add a durable red stall event, and keep automatic retries off to prevent duplicate inference or Tool execution.
- Add evidence-triggered, deduplicated tuning reminders. For a 32,768-token output maximum, the oMLX recipe calculates a 16,384-token Thinking Budget and warns that model-setting changes should be made only while idle; HarnessyXO never applies settings silently.
- Persist the local-LLM-first/backend-agnostic architecture invariant: provider adapters are optional enhancements and every shared behavior retains a generic fallback.
- Make compact Thinking, Tool, and Event rows cardless and paragraph-tight while preserving rules, animated running ellipses, temporary expansion, and red failed-state text.
- Retain v0.6.5 explicit export checkboxes, generated-handover separation, prompt-only timeline replacement, archive-family deletion, Project Files confinement, and instruction-interview layout without changing workspace schema 14.

## v0.6.5

- Replace the opaque five-choice **Detail level** menu in **Export Project / Chat** with an explicit checklist for User prompts, main responses, intermediate responses, Thinking, Tool calls/results, and referenced attachments.
- Let Intermediate, Thinking, and Tool rows independently use **Original text**, **AI summary**, or **Counts only**. Unchecking a row excludes that category, with validation preventing an empty transcript export.
- Preserve the previous Level 3 behavior as the new default: original User prompts and main responses with generated summaries of intermediate responses, Thinking, and Tool activity.
- Move **Generated project handover** into a separate export type with its own length control instead of presenting it as another transcript-detail combination.
- Show the summary model only when at least one selected row uses AI summary or the export type is a generated handover. Counts and original text remain inference-free.
- Restrict raw saved metadata to a complete Original-text transcript so metadata cannot silently reintroduce content that the user explicitly excluded.
- Retain the five legacy numeric export presets as an internal compatibility bridge while new exports use explicit, self-describing content selections.
- Retain every v0.6.4 timeline-density, operational-event, prompt-only edit/replace, archive, Project Files, and instruction-interview fix without changing workspace schema 14.

## v0.6.4

- Restrict **Edit & replace timeline** to a context menu opened on exactly one persisted User prompt. Thinking, Tool, HarnessyXO, event, blank-space, text-highlight, and multi-bubble selections never expose it; the existing server-side validation remains.
- Add browser-persistent **Thinking**, **Tools**, and **Events** display pills above the composer. Turning a pill off collapses matching cards to a one-line status plus horizontal rule; prompts and final answers always remain full.
- Keep compact live rows informative with fixed-width animated ellipses, terminal timing/outcome text, reduced-motion support, red failure styling, individual temporary expansion, selection cleanup, and scroll-anchor preservation.
- Persist request-time context-compaction events as soft-amber timeline cards with retry state, before/after token estimates, retained-history target, prefill estimate/ceiling, and an explicit statement that transcript, memory, task state, attachments, and Project Files were not deleted.
- Add persistent indigo automatic-continuation cards, neutral model-slot waits after ten seconds, and red run-blocked cards. Operational cards are presentation-only: they are excluded from model context, token accounting, exports, and ordinary conversation APIs.
- Hide routine output-route icons from Thinking and answer headers. Only genuine channel warnings or uncertainties retain a short marker; detailed backend fields, channel order, warnings, and uncertainty telemetry now appear in completed Run Stats and diagnostics.
- Retain every v0.6.3 archive, confined Project Files, instruction-interview, and persistent project-execution fix without changing workspace schema 14.

## v0.6.3

- Move sidebar-launched dialogs and notices onto a page-stable overlay so sidebar refreshes no longer delete elements still used by archive, child-project, or other menu callbacks.
- Give permanent archive sealing and archive-family deletion an indeterminate progress bar, spinner, elapsed timer, and disabled controls while the operation runs.
- Keep archived families draggable for ordering within **Archives**, reject every Active/Archives cross-section drag, and add explicit permanent deletion of the complete sealed family from any archived member.
- Make **Project Files** open at the logical `/workspace/Files` view containing only `References` and the current `Project-XXXX`; keep unrelated siblings hidden while displaying live parent/ancestor paths through their model-visible nested names.
- Enlarge the instruction-interview question counter and question text, and place them below the divider following **Ready for your answer.**
- Remove **Keep through this prompt** from both the UI and workspace API. **Edit & replace timeline** remains the single historical-prompt timeline edit, with **Undo latest rewind** as its recovery path.
- Retain the v0.6.2 persistent project execution view and workspace schema 14.

## v0.6.2

- Replace the v0.6 per-command project mount namespace with a project-isolated namespace retained for the lifetime of the running workspace VM. Mounts created successfully in one Tool call are now visible to later commands in that project.
- Add a root-owned namespace keeper with separate mount and PID namespaces, hidden controller state, strict project identity validation, raw-backing detachment, and per-command isolation probes.
- Recreate a retained namespace when the owned project, References root, or an ancestor directory inode changes, so rewind/undo and upstream root replacement cannot leave commands pinned to obsolete bytes.
- Fix the shell cwd mismatch caused by `/etc/profile.d/harnessy-workspace.sh` forcing every login shell back to `/workspace`. The final user-command trampoline now changes to and verifies the exact `Files/Project-XXXX` path after profiles load.
- Stop reporting an intended `working_directory` that differs from `pwd`; successful command telemetry now explicitly reports an enforced cwd and project-persistent mount scope.
- Tell the model that mounts are persistent across Tool calls and define the actual reset boundaries: explicit unmount, namespace repair/root replacement, VM stop, or VM rebuild.
- Retain every v0.6.1 instruction-interview, compact-dialog, and Send/queue control fix without changing workspace schema 14.

## v0.6.1

- Make instruction-interview answer submission transactional. HarnessyXO now asks the model to generate a valid next question before marking the current answer as accepted.
- If the model returns malformed interview JSON or the next-question request fails, keep the same question and exact multiline answer editable, re-enable **Answer & Continue**, and allow the user to revise and resend instead of leaving a dead `Q1 answered` row.
- Replace raw JSON decoder exceptions with a concise model-response error containing the useful line and column.
- Compact the instruction dialog: one collapsed **Interview context** section replaces several permanent context rows, and answered questions live under one collapsed **Interview answers (n)** section.
- Constrain long instruction-builder model names to the dialog width with ellipsis, hide the selector once a draft is ready, and replace unbounded autogrowing answer fields with fixed, internally scrollable text areas.
- Rebuild the composer Send/queue control as one clipped 68×42 px segmented pill. Remove the conflicting round-button geometry that made the Send circle overlap the rectangular dropdown segment.

## v0.6.0

- Replace historical prompt branching with live parent/child project dependencies. A child starts with a fresh chat, empty owned project directory, and fresh owned memory while receiving live read-only access to its parent/ancestor files and durable memory.
- Introduce the clean canonical workspace layout: `Files/References` plus one `Files/Project-XXXX` directory per project/chat. Human exploration, structured file tools, Git/LSP, and VM commands now operate on the same canonical bytes; unrelated projects are hidden from model tools.
- Rework rewind so only the selected project's chat, owned files, and owned memory move through time. Children survive unchanged and lazily reconcile current upstream file/memory changes on their next run. Add **Keep through this prompt**, **Edit & replace timeline**, and a real recoverable **Undo latest rewind** transaction.
- Replace private active rewind roots and `Open Working Files` with canonical Project Files. History remains app-private recovery data and can never become an active model working tree.
- Promote File History to a persistent application tab with version selection, preview, current/previous diffs, provenance, exact-version download, restore-as-copy, replace-current safety snapshots, and deleted-file browsing.
- Make Archive an irreversible family-sealing operation. Archiving a project permanently archives its complete descendant subtree, preserves the hierarchy and contextual snapshots, removes active project directories, and provides no unarchive/drag-back path.
- Add **Global Agent Slots** as the single normal concurrency ceiling shared by complete top-level runs and temporary read-only subagents. Related parent/descendant projects serialize; unrelated projects may fill free slots. One-slot delegation transfers the sole slot while the coordinator waits.
- Replace fixed run lanes with a dependency-aware global queue. Sidebar projects show global queue positions; the status footer shows active/available agent slots; queue details identify active coordinators/subagents and dependency/capacity waits.
- Add the read-only `delegate_task` tool, bounded per run, with coordinator-only durable file/memory commits and per-subagent timing/token/wait metrics in clickable run statistics.
- Separate Global Agent Slots from the advanced per-model **Backend concurrent model requests** limit, so a one-request oMLX backend safely serializes inference even when multiple agents can perform other work.
- Keep four-character non-confusable project IDs, prefer a distinct first character while available, render the title and ID as one selectable sidebar object, and annotate `Project-XXXX` explorer rows with the owner title without changing the folder name.
- Extract uploaded archives into a uniquely named folder inside the owning canonical project; never switch the chat to a hidden imported working root. Constrain browser File Explorer uploads to `Files/` on both VM and host-only workspaces.
- Preserve integrated username/password accounts, native user management, ntfy completion/reply support, pin/lock behaviour, explicit-only packaging, direct downloads, and the macOS/Linux no-auto-open launcher.
- This is an intentionally breaking clean-start workspace schema. v0.6.0 does not migrate v0.5.x workspace layouts; opening one fails clearly without renaming or mutating its files. Existing application settings and account records remain usable.

## v0.5.6

- Embed Users / Password in the main Settings dialog with native account controls and confirmations; no standalone management application or iframe.
- Share HarnessyXO's green/neutral light and dark theme between the app, initial setup, login and logout. Respect the saved appearance preference on every auth-page render.
- Preserve current-password confirmation, bounded authentication work, session revalidation/revocation and short-password support in the native account bridge. Clear password fields on submit and close.
- Redirect legacy account-page bookmarks to integrated Settings; keep existing credential files and workspaces unchanged.
- Recover expired/revoked sessions from the browser independently of Socket.IO, so changing your own password returns to sign-in even after the protected connection closes. Network outages do not falsely trigger sign-out.

## v0.5.5

- Fix native browser form submissions being rejected by the Origin check: change both HTTP and HTML referrer policies from no-referrer to same-origin on setup, login, logout and account-management pages.
- Retain strict rejection of missing, null and cross-origin mutation requests; do not weaken CSRF checks or restore token URL login.
- Add response-policy-driven form regressions and optional real-browser setup/account coverage; preserve short-password support and existing account records.

## v0.5.4

- Remove the 12-character password minimum throughout setup, account creation, password changes/resets and login; any non-empty password is accepted.
- Remove matching browser minimum-length validation and help text. Existing accounts, salted password hashing and other authentication safeguards are unchanged.
- Add short-password browser-flow regressions and retain the latest ten verification reports.

## v0.5.3

- Replace per-launch token URLs with browser first-account setup and persistent username/password authentication.
- Guard first-admin enrollment with a terminal-only one-time setup code; keep setup secrets out of diagnostic console capture.
- Add browser admin account management and password changes with reauthentication, last-admin protection and session revocation.
- Store salted password hashes in a separate protected settings file; all accounts are full admins for now.
- Remove automatic browser opening and its saved preference/UI setting.
- Protect HTTP/file routes and live connections; reject cross-origin mutations and bound authentication work and sessions.
- Extend credential redaction/exclusion in diagnostics and preserve all previous workspace and explorer fixes.

## v0.5.2

- Shorten public Project/Chat IDs to four non-confusable alphanumeric characters, unique within each workspace; prefer distinct starting characters, then least-used prefixes after alphabet exhaustion.
- Migrate registered eight-character IDs and output folders, preserving file contents and chat UUIDs with restart-safe journaled renames. Historical transcript paths are intentionally not rewritten.
- Make chat name and public ID one selectable sidebar button, including hover/focus/active styling.
- Show a small parenthesized owner title beside output folders as display-only text; handle renamed, archived, deleted and unassigned owners.
- Fix repeated Up navigation and deleted-context error notifications; retain v0.5.1's NiceGUI menu/API repairs.
- Add focused allocation, migration, interruption, collision, real-NiceGUI selection/navigation/annotation regressions; retain the newest ten verification reports.

## v0.5.1

- Reconcile runtime mount bindings before reusing an already-running VM across upgrades; preserve disks and worktrees.
- Fix v0.5.0 workspace-wrapper argument ordering and add executable Bash ABI/projection tests.
- Distinguish unavailable projections/nonzero probe exits from a successfully observed nonce mismatch; retain privacy-safe failure codes.
- Stop agent runs mechanically after mapping/cross-view failures, save skipped tool-batch replies, and retain partial-write warnings.
- Add read-only chat Working Files inspection, per-file SHA-256/root/path identity dialogs, direct single-file download attachments, and per-code-block Copy controls.
- Persist structured read/write before/after receipts in diagnostic logs and `FILE_OPERATIONS.json`; add `get_file_fingerprint` and optional shell `verify_paths`.
- Refresh output ownership each tool invocation; reject parent traversal, sibling symlink writes and root removal; search the live output overlay instead of stale private copies.
- Pass the same output projection policy through language-server probes and processes.
- Fix empty-file VM hash verification and unsupported File History context-menu arguments.
- Document incident evidence, safe upgrade/recovery, journal limits and output-guard security limits; retain the newest ten verification reports.

## v0.5.0

- Give every existing and new Project / Chat a durable eight-character, non-confusable alphanumeric ID and display it beneath the chat name in the sidebar.
- Create a matching `Files/<ID>_output` delivery folder without moving existing files; preserve that folder after chat deletion and tombstone its ID so it is never silently reassigned.
- Direct research, notes, drafts, builds, caches, tests, and intermediate versions to the ordinary working area while reserving the chat output folder for final user-ready scripts, files, and folders.
- Add a core `publish_output` Tool which copies completed items into the current output folder, preserves natural file/folder form, and refuses silent overwrite.
- Allow every chat to read or copy sibling outputs while blocking structured write, replace, move, delete, copy-destination, and working-directory mutations outside its own output folder.
- Project the current output read-write and sibling outputs read-only into every VM shell/process/Git namespace, keep raw backing mounts detached, and remove temporary private-worktree mountpoint directories after the command exits.
- Keep ZIP packaging explicit, copy a requested package into the current output folder, and exclude all output folders from package inputs to avoid recursive or cross-chat delivery capture.
- Add Base Files **File History** with a split version/preview/diff/details dialog, exact-version download, restore-as-copy, replace-current confirmation, originating-prompt navigation, and a browser for deleted or renamed historical paths.
- Reuse immutable shadow Git/large-object checkpoints, backfill retained prompt checkpoints into a chat-independent history catalogue, and take a complete safety snapshot before any restore.
- Migrate workspace databases to schema v11 without moving existing work or rebuilding VMs; add focused ownership, migration, projection, history, restore, packaging, prompt, and UI regressions.
- Retain exactly the newest **10** `VERIFICATION_v*.md` records.

## v0.4.12

- Add a persisted, machine-wide Project/Chat run queue that survives browser refreshes and application restarts without storing controller state inside model-visible workspace files.
- Hold a configured run lane for the complete AgentRunner lifecycle so Projects/Chats in one lane finish serially instead of alternating model and Tool turns.
- Reuse the existing concurrent-generation setting as the explicit full-run lane limit: one lane remains the safe default, while higher values permit parallel serial lanes without guessing hardware capacity.
- Add lane recommendations which prefer a free parallel lane, otherwise select the shortest queue, and keep every job for the same chat in one lane.
- Add a composer send dropdown for the recommended lane, each explicit lane, and the global run-queue view while retaining the main Send button and the separate same-run follow-up behavior.
- Show `lane · position` badges on queued Project/Chat rows plus aggregate workspace queue counts; the queue dialog supports pending-job removal and stopping the active job.
- Reserve queued attachments so they cannot be sent twice, restore them when a pending job is cancelled, and carry the selected model profile and Thinking choice into delayed execution.
- Run persisted jobs without an attached browser, preserve ntfy terminal alerts, fail Ask-only headless Tool approvals closed, and continue later pending jobs after one completes or fails.
- Mark a process-interrupted active job without replaying its potentially checkpointed prompt; untouched pending jobs remain resumable.
- Make each final **Completed in …** timer open run-specific statistics covering queue wait, full runtime, model/prefill/decode/Thinking/answer/Tool phases, tokens, cache, TTFT, throughput provenance, weighted speeds, and cost.
- Persist a run ID on User, assistant, Tool, error, and stopped records so a multi-step run's metrics can be aggregated exactly; older records use a clearly labelled nearest-prompt fallback.
- Add focused persistence, restart, lane-serialization/parallelism, attachment-reservation, headless-worker, UI-wiring, and run-metadata regressions; retain exactly the newest **10** verification records.

## v0.4.11

- Add a stable opaque `working_root_id`, root kind, and root label to filesystem telemetry so Base Files, imported copies, historical branches, and timeline rewinds cannot masquerade as one logical `.` root.
- Add exact whole-file SHA-256/byte receipts to `read_file`; hashes describe the same byte snapshot used for returned content rather than a later second read.
- Make `write_file` and `replace_in_file` flush and re-read host bytes, freshly prove the selected VM mapping, and compare the exact file digest/size inside the isolated VM before returning a confirmed result.
- Return `write_applied: true` with a failed result when the host mutation occurred but VM confirmation failed; reserve `FILE_VIEW_MISMATCH` for a fresh same-path, same-root digest mismatch.
- Extend `get_workspace_state` with an optional targeted path comparison and tighten the core prompt so differing-root or historical observations cannot be narrated as current file-tool/VM inconsistency.
- Fail closed with `ACTIVE_ROOT_CHANGED` if a run's captured working copy is no longer the chat's active root, instead of allowing a late tool call to touch the stale selection.
- Label each chat's working-copy kind in the footer and mark the workspace-level File Explorer and Terminal explicitly as **Base Files**.
- Add focused root-identity, hash-receipt, successful verification, mismatch, targeted-diagnostic, prompt, and UI regressions; retain exactly the newest **10** verification records.

## v0.4.10

- Add a route indicator to every newly generated Thinking and Answer bubble. Its tooltip shows the exact backend source field, chunk/character counts, backend label, mechanical classification, and observed reasoning/answer channel order.
- Preserve original native Ollama field identity (`message.thinking` / `message.content`) even though the client normalizes those values for the runner; OpenAI-compatible and oMLX streams retain their exact `delta.*` or buffered `message.*` field names.
- Make the boundary explicit: HarnessyXO renders backend reasoning fields as Thinking and backend content fields as Answer, and records that Answer bytes were not reclassified from Thinking.
- Show a limited-evidence indicator when Thinking is enabled but no separate reasoning field arrives. The UI explains that the backend may have returned only final text or folded reasoning into content and that HarnessyXO cannot distinguish those cases.
- Warn only on concrete stream structure: explicit `<think>` / `<analysis>` markers in answer content, reasoning output after answer output began, simultaneous reasoning/content deltas, or multiple non-empty reasoning aliases. Do not semantically judge prose as “thinking-like.”
- Persist provenance through live/reloaded transcript grouping, alternating reasoning/answer phases, tool and continuation steps, and browserless ntfy execution. Legacy messages remain unlabelled rather than receiving invented provenance.
- Keep provenance diagnostics privacy-safe: logs and the dedicated metadata summary contain field names, counts, transitions, and flags but no generated text.
- Add focused runner, transcript, privacy, interleaving, ambiguity, warning, live-event, UI, and legacy-compatibility regressions; retain exactly the newest **10** verification records.

## v0.4.9

- Add opt-in two-way ntfy replies. A phone-authored topic message becomes the next User prompt for the Project / Chat associated with the newest successfully delivered run alert.
- Run an idle reply target without requiring an attached browser page; route replies received during an active run into the existing safe model/tool-boundary follow-up queue.
- Subscribe through ntfy's JSON stream without opening an inbound host port. Establish a non-delivering startup cursor, recover short disconnect gaps from the last observed ID, deduplicate replayed IDs, and ignore every HarnessyXO-authored alert/acknowledgement using a dedicated outbound tag.
- Add a configurable 1–10,080 minute reply window, a 4,000-character input limit, explicit receipt/queue/rejection acknowledgements, and session-local reply targeting. Test alerts and cached messages from before startup never create surprise agent runs.
- Preserve lock semantics: a locked chat rejects remote input without mutation and points the user to unlock or create a historical branch. Timeline replacement, missing/deleted targets, expired targets, empty messages, and oversized messages fail closed.
- Preserve existing Tool permissions for phone-started runs. On/Off remain effective; Ask-only actions are denied because a headless run has no approval dialog. Settings warns that the secret topic becomes remote prompt authority.
- Add settings migration v12 with inbound replies disabled for every existing installation, while retaining all v0.4.8 private-worktree isolation behavior.
- Retain exactly the newest **10** `VERIFICATION_v*.md` records in release packages.

## v0.4.8

- Move VM imported projects, historical branch roots, and same-chat rewind roots out of model-controlled `Files/` into `.harnessy/worktrees/{imports,branches,rewinds}`.
- Add an automatic one-time migration for v0.4.3–v0.4.7 workspaces. Legacy children are atomically renamed, SQLite working-root references are transactionally rewritten to portable private references, and ambiguous source/destination collisions fail closed without deleting either copy.
- Give every model shell, process, structured Git/LSP action, and workspace terminal an isolated mount namespace containing exactly one selected root at `/workspace`; detach both raw Files and private-worktree backing mounts before the requested command starts.
- Reconcile both narrow Lima backing mounts after workspace moves/copies and VZ checkpoint restores. Do not mount the `.harnessy` metadata root wholesale.
- Hide legacy reserved worktree names from the base File Explorer and structured file tools as defense in depth, and exclude them from packages if a stale/manual copy exists.
- Add regression coverage proving that deleting the complete model-visible base `Files/` tree cannot delete a private branch, migration preserves all import/branch/rewind data and references, collision handling is non-destructive, and generated Lima namespace wrappers are valid shell.
- Retain exactly the newest **10** `VERIFICATION_v*.md` records in release packages.

## v0.4.7

- Add **Settings → Notifications** with zero-registration ntfy configuration, secure 192-bit topic generation, locally rendered phone-subscription QR, topic/link copy controls, and an explicit test-notification action.
- Send one app-owned alert when an agent run reaches normal completion or a terminal error. Manually stopped and finite-step-limit runs are separately selectable, and successful/stopped alerts can use a minimum-duration threshold while errors remain immediate.
- Keep notification delivery outside the LLM and its Tool permissions. The model never receives the ntfy server/topic, cannot invent notification success, and does not need an inbound webhook or exposed host port.
- Send only outcome, duration, and optionally workspace/Project/Chat names. Never include prompt/answer/reasoning text, Tool data, filenames/paths, or backend error details; redact `*secret*` fields from structured diagnostics as defense in depth.
- Track delivery in a non-blocking background task. Configuration/network/HTTP failure is logged with a privacy-safe reason and cannot delay, alter, or fail the already completed agent run.
- Add settings migration v11 with ntfy safely disabled for existing installations and retain exactly the newest **10** `VERIFICATION_v*.md` records.

## v0.4.6

- Add persistent **Pin / Unpin** actions for workspaces and Projects/Chats. Pinning preserves the row's current index rather than promoting it to the top, replaces its grab handle with a pin, and rejects browser or backend reorder operations that would move a pinned anchor.
- Make live/archive moves atomic with pin validation, so a cross-section drop cannot partially archive a chat and then fail its ordering update.
- Add persistent **Lock / Unlock** for Projects/Chats. The lock occupies the sidebar spinner slot and replaces the active composer/upload controls with a read-only notice.
- Keep locked chats readable, exportable, and branchable while blocking continuation, transcript/timeline replacement, title, instructions, Current Task State, chat-scoped memory, attachment, active-root, archive, and delete mutations at the storage layer as well as in the UI.
- Preserve **Edit & branch from here** for locked source chats while disabling same-chat **Edit & replace timeline**.
- Migrate existing machine/workspace SQLite databases with unpinned/unlocked defaults, retaining all current order, chat content, lineage, and settings.
- Retain exactly the newest **10** `VERIFICATION_v*.md` records in release packages.

## v0.4.5

- Stop treating ordinary code/file creation as an implicit request to package the workspace. Python-script and similar implementation requests now leave the requested files in place and report their paths.
- Move `package_working_copy` out of the default Tool schema. It is activated only through deliberate discovery or the explicitly scoped Release Packaging skill.
- Add a host-side intent gate before approval, workspace locking, status display, or compression. The latest User message must directly request a ZIP, archive, packaged release, or whole-project/workspace export; incidental mentions and negative/diagnostic packaging language are blocked.
- Strengthen the core and Auto-skill instructions so Release Packaging cannot be used as a generic implementation-completion skill.
- Preserve the v0.4.2 worker-thread compression and cooperative Stop behavior for valid, explicitly requested exports.
- Retain exactly the newest **10** `VERIFICATION_v*.md` records in release packages.

## v0.4.4

- Render historical chat lineage as a depth-first tree in the left sidebar. Direct and nested child chats are indented beneath their parent with a connector and branch marker while retaining flat draggable rows.
- Persist the parent chat ID/title snapshot on every branch. A deleted parent's foreign key can safely become null without erasing the branch's “Branched from … · U·…” source label.
- Add **Edit & replace timeline** beside the non-destructive branch action. It keeps the same chat ID, removes the selected User prompt and its entire visible suffix, restores the verified pre-prompt checkpoint, and submits the edited prompt as the next turn.
- Restore files into a fresh private replacement root rather than mutating a shared workspace/import/branch root in place. VM replacements remain guest-visible under `/workspace/.harnessyxo-rewinds/`.
- Restore historical Current Task State and seed an isolated, independently evolving memory scope. Preserve prefix attachments, re-queue selected prompt attachments, and remove suffix-only private upload copies without unlinking a path still referenced by retained data.
- Require explicit destructive confirmation, block replacement while that chat is active, keep existing child branch chats intact, and warn that completed external device/network effects cannot be reversed.
- Make replacement failure-atomic: cancellation or database failure removes partial restored trees and leaves transcript, active root, checkpoints, Task State, memory, and attachments unchanged.
- Retain exactly the newest **10** `VERIFICATION_v*.md` records in release packages.

## v0.4.3

- Add true **Edit & branch from here** behavior for historical User prompts. A new timeline starts from the verified state immediately before the selected prompt, with the original prompt prefilled for editing and the original timeline left untouched.
- Add per-prompt, atomic history checkpoints covering transcript position, active-root files, Task State, model-facing memory/checkpoint state, and prompt attachment metadata. A User message is never persisted as rewindable unless its filesystem snapshot succeeded.
- Add a HarnessyXO-private bare shadow Git history for ordinary files. Empty file changes reuse the previous commit, all Git operations use explicit private Git/index paths, and process/thread history locks serialize capture/materialization.
- Preserve large and opaque files outside Git through immutable clonefile/reflink objects with safe copy fallback. Unchanged objects are reused; modified/deleted/created-after cases restore correctly without per-prompt ZIP packaging.
- Snapshot a project's own Git metadata separately and restore it only into the isolated branch copy. Original project HEAD, index, refs, status, and configuration remain untouched.
- Add isolated VM-visible and host-workspace branch roots, durable branch lineage/sidebar indicators, nested branch baselines, parent-deletion-safe attachments, and reload persistence.
- Add branch-local Workspace Memory seeded from the historical checkpoint; subsequent branch memory writes do not leak into the original timeline or vice versa. Historical Current Task State is restored independently as well.
- Run prompt checkpoints and branch materialization off NiceGUI's event loop, shield the atomic checkpoint boundary from Stop cancellation, and serialize workspace agent writers for first-release correctness.
- Warn that already-completed External Target mutations are not reversed, while keeping current user/admin settings rather than rewinding application configuration.
- Retain exactly the newest **10** `VERIFICATION_v*.md` records in release packages.

## v0.4.2

- Fix the reproduced HarnessyXO server hang caused by agent `package_working_copy` performing synchronous ZIP/DEFLATE compression on NiceGUI/uvloop's main event-loop thread. Packaging now runs in a worker thread, so HTTP/WebSocket servicing, transcript updates, Stop, and normal shutdown remain responsive while a large archive is being created.
- Make ZIP creation cooperatively cancellable between file chunks. Stopping an agent run sets a cancellation event, removes the temporary partial archive, waits for the packaging worker to exit, and does not register an incomplete artifact.
- Show `Packaging working copy…` as the live Tool status while the worker runs; the existing Tool elapsed timer continues to show duration.
- On macOS, replace Python `webbrowser` startup probing with `/usr/bin/open` through LaunchServices. This avoids the AppleScript `-10810` / `Can’t get application "chrome"` / `"firefox"` noise seen on startup. Launcher stdout/stderr are suppressed so the per-launch auth URL is not leaked through subprocess diagnostics.
- If macOS browser auto-open fails, HarnessyXO remains running, records a privacy-safe failure event, and prints the local authenticated URL as the fallback.
- Keep the v0.4.1 full-turn **Completed in …** timing and v0.4.0 External SSH Targets unchanged.
- Release-package verification retention remains the newest **10** verification records.

## v0.4.1

- Add a full-turn completion timer to HarnessyXO assistant bubbles. Final persisted Assistant results, user-stopped runs, and terminal error/stop notices now record the wall-clock time from the most recent submitted prompt until that turn finished, including tool calls, waits, and automatic internal continuations.
- Show that timer in the assistant header as **Completed in ...** while keeping the existing per-bubble observed stream timing intact. This answers the separate question of how long the whole request took end-to-end, rather than just how long one visible answer segment streamed.
- Preserve the existing per-model-call stats/metrics behavior; this change adds end-to-end turn timing instead of relabelling call timing.
- Keep release-package verification retention at the newest **10** verification records.

## v0.4.0

- Add workspace-scoped **External Targets** for controlled host-brokered SSH access to real test devices. SSH credentials remain on the HarnessyXO host and are never placed in the workspace VM, model context, Tool arguments, or Tool results.
- Add brokered agent tools: `list_external_targets`, `target_status`, `target_list_files`, `target_exec`, `target_copy_to`, and `target_copy_from`. The model can iterate on real hardware through an explicitly configured target without receiving a raw `ssh` shell or arbitrary LAN endpoint.
- Add a default **Test Sandbox** policy. Remote file/list/copy paths are confined to one configured absolute test root; obvious privileged/package/service/firewall/disk/lateral-SSH commands, protected system paths, parent traversal, and root SSH accounts are blocked in v0.4. The remote OS account remains the actual security boundary, so the UI explicitly recommends a dedicated non-root user without broad sudo rights.
- Add per-target model access: **Ask before protected target actions** or **Allow autonomously inside target sandbox**. Global Settings → Agent / Tools also gains an **External SSH targets** permission family, defaulting to Ask.
- Add target connection initialization/testing plus a small privacy-conscious action history. Target connection testing can create the configured remote root, while removing a target changes only HarnessyXO configuration and never deletes remote files.
- Use target-specific OpenSSH TOFU known-host state (`StrictHostKeyChecking=accept-new`) under private workspace metadata. Identity-file paths remain private and are never exposed to the model.
- Preserve the v0.3.24–v0.3.33 context/cache, oMLX recovery, Lima DNS, long-Tool, tab/bubble, drag, and technical-Markdown fixes unchanged.
- Release-package verification retention is reduced from 15 to the newest **10** verification records.

## v0.3.33

- Fix technical Markdown false headings in model transcript output. Before rendering Assistant/Thinking Markdown, protect ATX-like hash prefixes that are not followed by whitespace, so source lines such as `#define`, `#include`, `#!/bin/sh`, `#123`, and `##token` stay literal instead of becoming headings. Real `# Heading` / `## Heading` syntax remains unchanged.
- Keep fenced backtick/tilde code blocks untouched by the display normalizer, including hash-prefixed source lines inside those fences.
- Keep the fix presentation-only: persisted transcript content, stream segments, Tool/model data, and bubble copy payloads continue to use the original unmodified model text.
- Add compact explicit H1–H6 styling inside Thinking bubbles so intentional headings remain proportional to reasoning text instead of inheriting browser-default giant heading sizes.

## v0.3.32

- Prevent Shift-click bubble range selection from extending the browser's native text selection. HarnessyXO consumes the Shift-click pointer default only for selectable transcript bubbles; ordinary mouse-drag text selection remains native.
- Add **Copy highlighted text** to the transcript right-click menu when the right-click lands inside a real browser text selection. It copies exactly the highlighted text, without bubble headers, and does not disturb an existing multi-bubble selection.
- Rename transcript multi-copy actions to **Copy selected bubbles** and **Copy selected bubbles · content only** for clearer distinction from highlighted-text copy.
- Increase the compact tab workspace-name line from 9.5px to 10.75px while keeping the item/chat line larger and the tab bar at the same 44px minimum height.
- Make native drag/reorder motion materially more visible. Main tabs and sidebar workspace/chat rows use FLIP-style sibling animation while the dragged DOM node changes position, dragged sources receive a clearer lift/outline treatment, and File Explorer drags now visibly lift the source row and animate folder drop targets.
- Preserve v0.3.31 display-only workspace rename, bubble headers/multi-selection, v0.3.30 long-Tool timeout/status work, v0.3.29 Lima DNS repair, and the v0.3.24–v0.3.28 context/cache/finalization stack unchanged.

## v0.3.31

- Add safe **Rename Workspace** to the workspace `⋯` and right-click menus. Renaming changes only the HarnessyXO display label plus hidden workspace metadata; the filesystem folder, Lima VM identity, mounts, chats, memory, and workspace IDs remain unchanged.
- Redesign main tabs as a compact two-line label: muted workspace name on top, then the item icon plus chat/tool/file name below. The bar stays approximately the same height and both lines ellipsize independently.
- Make transcript bubbles permanently selectable without a separate mode. Click focuses one bubble, Shift-click selects a contiguous range, Ctrl-click / Cmd-click toggles individual bubbles, right-click preserves an existing multi-selection, and Escape or clicking blank transcript space clears it.
- Add one transcript context menu with **Copy selected**, **Copy selected · content only**, and **Clear selection**. Multi-copy follows chronological DOM order and uses the same self-identifying headers as individual copy.
- Make the individual bubble copy glyph visually smaller while preserving its existing click target. Individual copy continues to include the relevant `User`, `Thinking`, `Tool: <name>`, or `HarnessyXO` header.
- Hide copy controls on the currently incomplete/generating Assistant/Thinking or Tool bubble. The control appears when that bubble reaches a durable completion boundary; earlier completed bubbles remain copyable during the same agent run.
- Bound multi-copy provider memory to the currently mounted transcript window so virtual-history browsing cannot retain old large Tool payloads indefinitely.

## v0.3.30

- Show expanded live `run_command` elapsed/timeout status from the 10-second mark instead of waiting 30 seconds.
- Raise the model-visible, runtime and Settings shell-command timeout ceiling from 1,800 seconds to 7,200 seconds (2 hours), while preserving the existing default timeout.
- Keep silence informational only: long commands remain governed by their requested timeout, not by a no-output watchdog.

## v0.3.29

- Fix Lima guest DNS under the workspace private-LAN egress guard. When `/etc/resolv.conf` points only at systemd-resolved's `127.0.0.53` stub, collect the real upstream resolver from `/run/systemd/resolve/resolv.conf` and a bounded local `resolvectl dns` query before private-range rejects are installed. This permits TCP/UDP 53 only to runtime-configured resolvers (including private Lima gateway DNS such as `192.168.5.2`) while preserving the existing rejection of arbitrary `192.168.0.0/16` and other private ranges.
- Keep network-guard startup deterministic: resolver discovery performs no hostname lookup and bounds the `resolvectl` inspection to two seconds.
- Make long `run_command` Tool execution visibly alive. After 30 seconds the Tool header shows elapsed time, the effective command timeout, and `no live output`; other Tools keep the compact elapsed label. This reflects the current VM execution layer, where command output is buffered until Tool completion, and avoids a redirected/silent installer looking frozen for most of a 25-minute timeout.
- Preserve v0.3.28 finalization recovery, v0.3.27 oMLX context recovery/cache-hit telemetry, and v0.3.26 cache-stable context diagnostics unchanged.

## v0.3.28

- Harden post-tool finalization for local models that immediately EOS after a successful continuity/memory housekeeping tool. `update_task_state`, `remember`, and `update_checkpoint` now return an explicit model-facing next-action reminder that the housekeeping operation does not complete the user-facing turn; if work is complete the model must provide the concrete final answer rather than ending empty.
- Strengthen bounded missing-final-answer recovery without touching the cache-stable leading prefix. If the most recent Tool result is a housekeeping tool, the first recovery suffix explicitly requests finalization; a second empty recovery escalates to a mandatory finalization instruction requiring either visible final-answer text or an executable Tool action.
- Preserve the existing two-retry infinite-loop guard and structured `missing_final_answer` terminal stop if the backend/model still produces unusable empty turns.
- Keep v0.3.27 oMLX prefill-memory recovery and live cache-hit telemetry unchanged. The new recovery prompts are request-only suffixes, so they do not rewrite the stable cached prefix.

## v0.3.27

- Treat top-level oMLX streaming error objects as backend failures even when the HTTP stream was already opened with status 200. Specific oMLX prefill-memory rejection wording is normalized to the existing `prefill_memory_exceeded` recovery code when older server builds omit the structured code.
- Prevent a rejected ~158K prefill from falling through to the generic empty-completion path and being blindly submitted again. The existing bounded one-shot recovery now receives the real failure.
- Keep the selected Retained live context policy unchanged during recovery. Maximum/large policies retry with at most a 96K retained-history recovery epoch; an already-96K-or-smaller policy shrinks by 25% for the single retry. Persisted transcript, memory, task state, attachments and project files remain untouched.
- Show actual oMLX cache reuse during live Prompt Processing. Prefer a direct activity cached-token field when present; for a local oMLX server, otherwise correlate the activity request UUID with the numeric-only `prefix cache: request … re-prefills … (reused …)` line appended to `~/.omlx/logs/server.log`. Show cache-hit %, cached tokens, and progress through the uncached suffix. Never export or retain raw log lines/prompt content, and do not manufacture a rate when neither signal exists.

## v0.3.26

- Finish the three-checkpoint context/cache work with privacy-safe consecutive-request prefix diagnostics: estimated common-prefix tokens, current/previous reuse percentages, append-only/identical state, cache-health classification, and the first changed coarse prompt region. Only run-local digests are used for comparison; prompt/tool/file content and the digests themselves are not persisted.
- Join backend-reported cached-token accounting to the same Context diagnostics when the provider exposes it, while keeping the HarnessyXO estimate explicitly separate from backend truth.
- Show context epoch/cache health in the Project / Chat Performance / Context dialog and summarize cache health in the normal context tooltip.
- Refactor adaptive retrieval retention so an old retained read no longer expands the hot-history start boundary. Omitted retained evidence becomes a bounded request-only late capsule containing only the exact retained Tool result; capsules can be dropped first under hard budget pressure and never alter saved transcript/history.
- Place one-shot historical visual reactivation after the append-only Tool tail so reactivated images affect the suffix rather than splitting the backend's reusable text prefix.
- Preserve v0.3.25 cache-stable epochs, v0.3.24 per-model retained-context controls, recent/current Tool evidence protection, oMLX prefill-memory recovery, SQLite-authoritative continuity state, and privacy-safe diagnostics.

## v0.3.25

**Context/cache checkpoint 2 of 3 — cache-stable run epochs**

- Replace continuously sliding request-history selection during an autonomous AgentRunner run with **cache-stable context epochs**. The first request freezes a base prefix; newly persisted assistant/Tool/user messages append after it instead of causing older prefix content to be continuously reselected.
- Snapshot Current Task State and Workspace Memory in the run's leading system prompt. Tool updates remain immediately visible through Tool results, while the front of the prompt no longer changes merely because `update_task_state`, `remember`, or `update_checkpoint` changed durable state mid-run. A new AgentRunner/user run captures the latest durable values.
- Make long-chat archive guidance a static system component from the first request, eliminating the former conditional leading-system edit when archiving first became active.
- On genuine budget pressure, create one new compacted epoch and leave append-only runway equal to 15% of usable history capacity, bounded to 12K–32K tokens. This prevents repeated one-block-at-a-time compaction from invalidating the prefix on every subsequent Tool step.
- Keep post-epoch Tool results exact until a deliberate epoch transition; existing old-first compaction/archive semantics preserve the newest evidence as long as capacity permits.
- Keep historical-image reactivation as a one-shot late-context capsule so requesting an old image does not become part of the frozen prefix.
- Append automatic continuation steering as request-only late user context instead of mutating the system message.
- If a runtime context probe or oMLX prefill-memory recovery compacts the in-memory request, adopt that compacted view as the next stable epoch rather than rebuilding the larger pre-recovery prompt on the following step.
- Add request-budget telemetry for the fixed input cost, effective request limit, and compacted Tool message IDs to support checkpoint-3 cache diagnostics.
- Fix the package-version mismatch left in checkpoint 1 so `VERSION`, `harnessy.__version__`, README and release tests agree.

## v0.3.24 — Context/cache checkpoint 1 of 3

- Add a per-model **Retained live context** control under Settings → Models → Context with Auto / Balanced, 96K, 120K, 160K, 192K, Maximum, and Custom choices.
- Define **Maximum** as removal of HarnessyXO's historical 96K hot-tail cap, while still honoring the observed/configured runtime context, maximum-output reserve, safety margin, system instructions, and tool-schema cost. It does not preallocate or force a full-context request.
- Resolve the live-history ceiling against the runtime actually observed by the backend when available, so Maximum/Custom cannot silently exceed a smaller active runtime.
- Preserve the old undocumented `agent.context_hot_tokens` setting by migrating it into each model profile as a Custom retained-context policy; direct legacy `AgentRunner` callers remain compatible.
- Add retained-context policy telemetry to Context diagnostics so the selected mode, requested ceiling, and resolved hot-tail target are visible.
- This is checkpoint 1 only. Cache-stable run epochs, mutable-prefix freezing, adaptive-retention refactoring, and prefix-stability diagnostics are deliberately deferred to checkpoints 2 and 3.

## v0.3.23

- Add compact per-block copy controls for User, Thinking, Tool, and HarnessyXO transcript bubbles. Tool copy uses the complete invocation/result payload rather than the collapsed UI summary; live copy state follows streaming updates and persisted blocks expose compact stable references, including distinct references for split assistant segments.
- Strengthen the agent grounding contract for cheaply testable negative environment assertions. Claims such as cannot-mount, permission-denied, loop-device/tool/network unavailable, missing file, or read-only filesystem must be freshly targeted and verified before being stated as current fact; unrelated Tool success is not evidence for a different claim, and old failures remain historical unless revalidated.
- Enrich privacy-safe shell diagnostics with fixed-allowlist executable/operation classes, option names, compound/control-operator structure, failure-masking indicators, recognized error/errno classes, and per-command VM generation/boot deltas. Unknown/custom executable basenames are never exported.
- Detect the important `overall shell returncode == 0` plus recognized inner error case (for example an error masked by `|| true`) without exposing raw stderr. Error-signature extraction prefers stderr/explicit stderr merging so ordinary stdout/file content containing words like `Permission denied` is not misclassified.
- Add privacy-safe model environment-claim labels and a bounded `ENVIRONMENT_TIMELINE.json` to the default diagnostics ZIP, correlating claim markers with VM lifecycle/mapping and shell evidence while still stripping model prose, commands, operands, paths, file contents, and raw tool output.
- Continue the 15-record verification retention policy by replacing the oldest retained verification record with `VERIFICATION_v0.3.23.md`.

## v0.3.22

- Make Prompt Navigator selection mutually exclusive: the follow-bottom triangle and a user-prompt square can never be highlighted at the same time. While actively following the real newest page, only the triangle owns `aria-current`; an explicit prompt jump pauses follow mode and keeps that prompt square selected even if the prompt is physically bottom-clamped.
- Give the isolated Instruction Interview a bounded **read-only reference context** containing recent Workspace Memory plus compact summaries of other Projects/Chats (saved Project/Chat Instructions and Current Task State). The current Project/Chat is excluded. The dialog shows the exact snapshot it may use.
- Let the interviewer use that reference only to recognize potentially related prior work and avoid needless repetition. A plausible match may trigger one relationship question (continuation, related alternative, related-but-independent, or unrelated), but similarity never causes automatic inheritance or memory mutation.
- Stop the interviewer from pushing discoverable execution facts back onto the user. Filenames/paths, mount or extraction state, source locations, package/tool versions and other inspectable state should be discovered by the eventual agent; explicit “find it / look it up / figure it out” answers are reinforced at controller level instead of being re-asked.
- Repair one stale v0.3.20 Prompt Navigator source-shape test whose selector assumption had already been invalidated by v0.3.21's combined dot/tail CSS selector.

## v0.3.21

- Strengthen the isolated Instruction Interview with an explicit completeness audit before READY, expanded awareness of fidelity, scope/non-goals, priorities/trade-offs, analysis versus target environment, evidence hierarchy, external research, autonomy/escalation, fallback behavior, portability/dependencies, modification boundaries and concrete completion criteria. Workspace and Project/Chat scopes use deliberately different coverage priorities.
- Treat a READY response with non-empty `remaining_material_ambiguities` as internally inconsistent and force one clarification instead of accepting an early draft. Preserve the 12-question bound and mandatory final “Anything else?” review.
- Remove the legacy Project / Chat Templates UI and composer shortcut. Existing legacy settings data remains inert for rollback compatibility.
- Replace the four HarnessyXO header shortcut icons with one right-aligned `⋯` action menu containing Home File Explorer, Home Terminal, Settings and Download Diagnostics.
- Give Workspace File Explorer a distinct `folder_special` icon in workspace actions and workspace tabs; Home File Explorer keeps the normal folder icon.
- Add a dedicated Prompt Navigator tail control after the user-prompt markers. The downward triangle jumps to the latest transcript window and resumes follow-bottom mode without becoming a user-prompt marker.
- Keep only the 15 newest `VERIFICATION_v*.md` records in release packages.

## v0.3.20

- Add evidence-driven **adaptive retrieval retention** for exact persisted retrievals (`read_chat_message`, text `read_attachment`, and `read_project_memory`). Ordinary retrievals still use normal recency; stronger retention activates only after the same exact resource/range/content was retrieved before, was absent from the request that triggered the re-read, and therefore demonstrably had to be fetched again.
- Make retention identity deterministic using resource/range plus a content SHA-256, so similar queries, overlapping-but-different ranges, and changed content do not accidentally share retention state.
- Make the reset lifecycle explicit: promotion resets the observation baseline to the new retrieval; repeated reads during an active retained cycle refresh that cycle without double-promotion; expiry returns the item to ordinary observation; a later promotion requires a new proven loss event.
- Bound adaptive retention to six subsequent model steps and a 12k estimated-token aggregate budget. Release the least-recently-refreshed retained item when the working set would exceed that budget, skip oversize single-item promotion, and allow hard request pressure to release retention rather than deadlocking context assembly.
- Keep exact retained tool results ahead of ordinary compaction/archive candidates while retention is active, including across queued follow-up turn boundaries within the same agent run. Add context telemetry for active retained retrievals, retention budget, and pressure releases.
- Add a root-level `FEATURES.md` product/capability overview and link it from the README.
- Change Prompt Navigator markers from tiny circles to compact rounded squares with enlarged stable click targets in sparse chats, while preserving centered grouping, active-state behavior, virtualized locate, dense-chat compression, and the v0.3.15 bottom-clamp selection fix.
- Add adversarial reset/regression coverage, including 100 complete promotion/refresh/expiry/re-observation cycles to prove stale loss state cannot double-promote across reset boundaries.

## v0.3.19

- Recover objectively empty/no-action model turns with a bounded **ephemeral user continuation** rather than only mutating system guidance. The synthetic `user` turn is request-only, is never persisted as if the user typed it, and is attempted at most twice before HarnessyXO stops to prevent an infinite loop. Normal non-empty final answers still stop normally and never trigger this recovery.
- Replace the misleading broad `"tool call"` error-text classification for this path with a structured `missing_final_answer` terminal reason. Repeated empty completions now render as **Model returned no usable completion** instead of **Tool protocol failure**; genuine invalid-tool/protocol failures remain separate.
- Open text/Markdown files as first-class right-pane tabs instead of modal editor dialogs. Reopening an already-open file focuses the existing tab, and unsaved drafts survive ordinary tab switches.
- Give file tabs **Viewer / Edit** subtabs. Markdown Viewer renders Markdown; ordinary text/code Viewer is read-only source. Save remains conflict-safe, Revert reloads from disk, clean tabs refresh when agent-side file edits are detected, and closing a dirty file tab requires explicit discard confirmation.
- Preserve v0.3.18 privacy-safe diagnostics, v0.3.17 portable capability detection/Linux portability, v0.3.16 oMLX prefill recovery, and all existing VM/network/isolation behavior.

## v0.3.18

- Make **Download Diagnostics** privacy-safe by default. The exported ZIP strips conversation text, model reasoning/answers, prompt bodies, raw tool arguments/results, file contents, stream payload previews, and path/location values while retaining event timing, token/context metrics, finish reasons, error codes, tool names, argument shape/JSON validity and parse positions, backend state, and system snapshots.
- Add an explicit **Include conversation/model/tool content** opt-in, off by default. Opted-in exports use a separately named `HarnessyXO-Diagnostics-Latest-Including-Content.zip` so raw-content bundles cannot be mistaken for the privacy-safe default.
- Exclude raw console capture and raw crash files from privacy-safe bundles because arbitrary free-form output cannot be reliably proven free of project/chat content. Add `PRIVACY.txt` to every safe bundle documenting exactly what is removed and retained.
- Make `.logs/collect_diagnostics.py` privacy-safe by default as well; `--include-content` is required to intentionally export raw payload evidence. Previous-session structured tails are sanitized by the same rules.
- Preserve raw on-disk diagnostic recording inside the local HarnessyXO installation so local troubleshooting evidence is not weakened; sanitization occurs only when creating the shareable bundle.

## v0.3.17

- Replace the Ollama-only capability detector with a provider-agnostic detector for Ollama, oMLX, llama.cpp and generic OpenAI-compatible endpoints. Prefer passive provider/model metadata and preserve unknown fields instead of treating missing metadata as unsupported.
- Use oMLX `/v1/models/status`, llama.cpp `GET /props`, native Ollama `/api/show`, and generic `/models` capability/modality metadata when available. Manual **Detect Model Capabilities** may run at most two one-token API-shape probes for developer-role and strict-tool-schema acceptance; automatic/background detection never runs inference.
- Show per-capability evidence in Models settings as provider-reported, API-accepted/rejected, unknown, or manual override, and allow detected usage/thinking/API-compatibility fields to populate the existing switches.
- Audit macOS/Linux host portability. Headless Linux startup no longer attempts to open a graphical browser when no X11/Wayland/BROWSER session exists; the authenticated launch URL is still printed.
- Keep the workspace VM engine portable: Apple Silicon uses Lima VZ for same-architecture ARM64 guests, while Linux uses Lima QEMU for native or cross-architecture guests. Improve Linux Lima prerequisite guidance, retain apt/dnf QEMU/OpenSSH handling, and report KVM presence/accessibility as acceleration telemetry rather than a correctness requirement.
- Preserve v0.3.16 bounded oMLX prefill-memory recovery and all existing VM/network/isolation behavior.

## v0.3.16

- Recognize the structured oMLX `prefill_memory_exceeded` error code and recover without brittle message/regex matching.
- On the first rejection, compact only the in-memory request view to an emergency hot-history target and retry the same model step once; persisted transcript, memory, task state, attachments, and project files remain unchanged.
- If the retry is rejected again, stop cleanly with estimated-peak and permitted-ceiling memory figures plus practical remediation guidance. Never loop retries.
- Emit explicit status/event/diagnostic records for the recovery attempt so the UI and diagnostics show why the model call paused and retried.

## v0.3.15

- Make the full agreed Global Instructions text the shipped default, including autonomous maintenance of useful human-readable working documents for substantial investigation/RE/research/multi-phase work, with model-chosen descriptive filenames and structure. Existing authored Global Instructions remain preserved; Restore Default adopts the new text.
- Fix Prompt Navigator tail selection when the final prompt cannot physically cross the normal scrollspy marker because the transcript is bottom-clamped. Explicit dot clicks remain active through programmatic clamping, genuine user scrolling releases the click lock, and the true newest-page bottom resolves to the final prompt.
- Preserve the compact centered Prompt Navigator layout, virtualized locate behavior, instruction-entry flow, continuity state, VM/network behavior, and all v0.3.14 agent behavior.

## v0.3.14

- Add the requested anti-announcement rule verbatim to the default Global Instructions: if the agent states it is about to inspect, write, test, modify, or continue work, it must perform that action with the appropriate tool in the same agent run; a final answer means the task is complete or genuinely blocked.
- Preserve the existing absent-only/user-authored Global Instructions upgrade semantics. Existing installations are not silently rewritten; Restore Default stages the new default for explicit Save.
- Do not add phrase/pattern-based premature-stop recovery in this focused release.

## v0.3.13

- Make **Workspace Instructions** and **Project / Chat Instructions** open to a passive setup chooser. Opening either scope performs no inference and spends no model tokens; the isolated interview starts only after the user explicitly presses **Start LLM Interview**.
- Add direct **Enter manually** mode for both instruction scopes so instructions can be reviewed/edited/saved even when no model profile is available.
- Add **Copy from Project / Chat** for both instruction scopes, copying only a selected Project/Chat instruction document from the current workspace; transcript, Workspace Memory, Current Task State and files are never copied. Existing target instructions require explicit replacement confirmation.
- Add **Current Task State** to the shared Project/Chat `⋯` / right-click actions. The read-only inspector exposes objective, phase, completed milestones/findings, working artifacts, open questions, do-not-repeat items, resume notes, revision/time metadata, raw JSON, refresh, and a direct Workspace Memory link.
- Clarify in the task-state inspector where continuity lives: recent/cold chat history, per-Project/Chat Current Task State, and durable cross-Project/Chat Workspace Memory are separate stores.
- Strengthen agent continuity guidance so Current Task State stays bounded but detailed enough for a fresh model to resume after compaction without broad rediscovery; established cross-Project/Chat discoveries/decisions should be recorded in Workspace Memory when learned rather than deferred until the end of a long run.
- Preserve the v0.3.12 Instruction Interview flow, mandatory final review, navigation/confirmation fixes, Prompt Navigator layout, SQLite-authoritative storage, VM/network behavior, and optional-tool management.

## v0.3.12

- Contain nested workspace-picker File Explorer overscroll so a wheel/trackpad gesture at the explorer boundary does not scroll the parent dialog.
- Rework the Instruction Interview around one active question with collapsed history/examples, compact recommendations, a fixed action footer, bounded internally scrolling answer fields, and visible model activity/elapsed/backend phases while calls are running.
- Make the final **Anything else you'd like the model to know?** review a HarnessyXO-controlled mandatory step before every draft, including **Finish & Draft Now**; allow at most one targeted post-final follow-up when genuinely needed.
- Make single-clicking a workspace open/focus its Environment tab and derive workspace + Project/Chat sidebar highlighting from the active tab so tab-strip navigation and sidebar state cannot drift apart.
- Add explicit Archive Project/Chat confirmation and confirmations for clearing scoped instructions / removing HarnessyXO-owned supplemental bundles while preserving existing destructive VM/workspace/snapshot confirmations.
- Center sparse Prompt Navigator dots as one compact group with normal inter-dot empty space of about two dot diameters, preserving the existing **Show/hide prompt navigator** wording, active marker, click-to-jump, and virtualized locate behavior.
- Preserve v0.3.11 optional-tool reconciliation, outbound-off behavior, isolated instruction architecture, SQLite-authoritative memory/task state, and long-session/VM-mapping protections.

## v0.3.11

- Add **Environment → Manage Optional Tools** so workspace tool selection can be changed after creation rather than only in the workspace picker.
- Probe a running guest on demand and show each selectable tool as Installed / Not installed / Partial / Unknown. A stopped VM never starts merely to populate this dialog.
- **Apply / Retry Selected** saves the desired selection and installs only selected tools that are currently missing when the running VM has public outbound access. Stopped/offline VMs retain the selection for the next usable setup without attempting downloads.
- Do not write a completed provisioning marker while selected tools remain missing/partial, allowing later setup to retry them.
- Keep distro package deselection non-destructive; automatic apt/dnf removal is intentionally avoided. Add explicit safe removal for deselected HarnessyXO-owned Ghidra/Python-RE `/opt` bundles.
- Make post-creation tool reconciliation an exclusive environment operation so active agents/terminals/processes cannot race guest package changes.

## v0.3.10

- Fix the v0.3.9 Instruction Interview deadlock where the dialog set `busy` before its first scheduled `request_next`, causing the request routine to return without ever calling the selected LLM. Add a bounded builder timeout so backend failures become visible errors rather than permanent spinners.
- Keep background workspace provisioning backend-only; remove the illegal background `ui.notify()` that raised NiceGUI's empty-slot-stack RuntimeError after workspace creation.
- Widen Project/Chat action menus and keep icon/label rows on one line with deterministic alignment and ellipsis.
- Add per-preset optional-tool checkboxes to workspace creation, default all selected, with Select all / Clear optional controls and explicit heavy-bundle labels. Persist the exact selection in environment schema v2.
- Batch optional distro-package installation for materially faster first setup, fall back only a failed batch to individual packages, and surface the actual package/tool being processed in environment progress.
- Treat Public outbound OFF as authoritative: perform local integration checks only and skip all downloadable optional provisioning instead of attempting apt/dnf/curl/pip operations that cannot succeed. Reconcile selected tools when the network policy/configuration revision later changes.
- Make apt/dnf/service-hook non-zero output recoverable when verification proves all required packages are installed. Write the provisioning marker only after explicit package verification; keep Ghidra/Python/other optional tooling best-effort.

## v0.3.9

- Replace file-backed Workspace/Project instruction concepts with two optional SQLite-backed scopes: **Workspace Instructions** and **Project / Chat Instructions**. Both start empty. Effective order is Global → Workspace → Project/Chat; working-tree `PROJECT_INSTRUCTIONS.md` and old `.LLM` instruction files are ordinary/ignored files rather than instruction sources.
- Add the isolated **Instruction Interview**. The selected LLM asks one adaptive substantive question at a time, can recommend/sample answers and request material follow-ups, and is bounded by HarnessyXO. `Finish & Draft Now` forces a separate clean compiler call; generated instructions are previewable/editable and remain inactive until Save. The builder sees higher-level Global/Workspace instructions so it can avoid duplication, but receives no working transcript, tools, filesystem access, or memory-write capability.
- Rename user-facing chat surfaces to **Projects / Chats** / **Project / Chat** where appropriate. Add Project/Chat instruction actions and **View Effective Instructions** to the shared `⋯`/right-click action definitions.
- Make Workspace Memory SQLite-authoritative. The Memory editor and `read_project_memory` expose generated Markdown views of structured DB records/checkpoint state; `.LLM/PROJECT_MEMORY.md` is no longer authoritative. `.LLM/` remains available for workspace Skills.
- Keep CURRENT TASK STATE separate and per Project/Chat. Preserve v0.3.8 Markdown Preview/Edit fixes, v0.3.7 long-run continuity/loop guard, v0.3.6 Prompt Navigator, v0.3.5 workspace-mapping/lifecycle safeguards, and existing File Explorer/VM behavior.
- Intentionally provide no automatic migration from the v0.3.8 file-backed instruction/memory layout; new optional instruction scopes begin empty as requested.

## v0.3.8

- Clarify HarnessyXO's instruction/memory layers. `.LLM/WORKSPACE_INSTRUCTIONS.md` remains hidden workspace-wide user guidance, `.LLM/PROJECT_MEMORY.md` remains durable model-maintained workspace memory, and `Files/PROJECT_INSTRUCTIONS.md` is normal project content for mission/scope/constraints/deliverables.
- Add **Workspace/right-click → Project Instructions**. A new workspace gets an in-memory starter template and nothing is created until Save; saving an empty draft removes/disables the file. This removes the need to manually create/copy `PROJECT_INSTRUCTIONS.md`.
- Always inject the workspace-root `Files/PROJECT_INSTRUCTIONS.md` when present, even when a chat is working from a nested active root. A nested active-root `PROJECT_INSTRUCTIONS.md` may additionally specialize/override the workspace-root project instructions.
- Fix Markdown File Explorer Preview typography by applying the same `hy-assistant` Markdown sizing/rules used by normal chat answers, preventing default renderer headings from becoming disproportionately huge.
- Fix the Markdown file **Preview / Edit** tabs by replacing server-driven visibility toggles with native NiceGUI/Quasar tab panels. Preview stays synchronized with the draft; Edit is now a real client-side panel switch.
- Keep v0.3.7 long-run continuity, task-state/loop safeguards, 96k large-context hot tail, and shared right-click/`⋯` menus unchanged outside these additions.

## v0.3.7

- Add a per-chat **CURRENT TASK STATE** continuity ledger outside ordinary transcript compaction, with `get_task_state` / `update_task_state` model tools and bounded objective, phase, next-action, completed, artifact, open-question, note and do-not-repeat fields.
- Automatically supply the active root `PROJECT_INSTRUCTIONS.md` as a hashed system component so compaction does not trigger repeated task-file rereads. The latest user instruction still overrides stored continuity state.
- Raise the default hot-history target for large-context models from the old 48k cap to a 96k cap (262,144-token profiles now default to 96k), while retaining runtime/effective-context budget enforcement. Expose hot-tail target and assembled/effective context pressure in Metrics.
- Add a semantic rediscovery-loop guard for repeated broad workspace inventories, task rereads and workspace-identity checks without productive progress. Repeated orientation actions fail as `AGENT_LOOP_GUARD` and direct the model toward CURRENT TASK STATE or a specific artifact.
- Add truncation guidance to broad `list_files` and `run_command` results: do not repeat/broaden a truncated inventory; narrow the next query.
- Keep old assistant hypotheses out of automatic warm archive retrieval. Historical assistant prose is recalled only when the user explicitly asks what the assistant previously said; user-history retrieval remains available normally.
- Add right-click context menus to workspace and chat rows. Right-click and existing `⋯` menus share the same menu-population functions so their available actions stay identical.
- Preserve v0.3.6 Prompt Navigator and v0.3.5 workspace-mapping/lifecycle telemetry without changing production SQLite durability or VM filesystem semantics.

## v0.3.6

- Add a left-edge **Prompt Navigator** to chat transcripts. One compact dot is generated for every persisted user prompt; the dot nearest the current reading position is highlighted and hovering a dot shows its prompt number plus a short preview.
- Clicking a dot jumps directly to that user turn. Prompts outside the currently mounted long-chat window use the existing bounded transcript `locate` transaction, so navigation does not load or walk every intermediate message.
- Keep live sends represented without inventing durable transcript IDs: an ephemeral navigator-only identity is used while generation is active, then replaced by the persisted prompt on the normal transcript refresh.
- Compress marker size automatically for very long chats, keep the rail fixed to the left edge of the chat content, and preserve transcript/composer/status geometry.
- Add **Chat ⋯ → Show/hide prompt navigator**. The preference is global, persisted in HarnessyXO settings, defaults on, and does not alter chat/message storage.
- Add lightweight SQLite prompt-index retrieval so the navigator reads only user message IDs/timestamps and truncated previews rather than materializing the whole virtualized transcript.

## v0.3.5

- Prevent long-chat filesystem/VM confabulation from being treated as infrastructure telemetry. Agent guidance now requires explicit HarnessyXO signals for VM boot/restart, destructive lifecycle operations, Files identity changes, and host↔guest mapping divergence.
- Add persisted Lima lifecycle generation/event telemetry and expose boot/readiness identity with filesystem/shell tool results.
- Add `get_workspace_state`, which performs a fresh one-time nonce proof that host `Files/` and guest `/workspace` are the same backing mapping. Shell, structured Git and process starts fail closed on a verified mismatch instead of executing against an unverified different tree.
- Use temporary mapping probes only; no persistent marker is written into the user's project. Probes are deleted before user/model commands execute, hidden from file tools/File Explorer, excluded from ZIPs, and placed under `.git/info` for root Git repositories so status remains clean.
- Distinguish `FILE_NOT_FOUND`, `COMMAND_EXIT_NONZERO`, `VM_COMMAND_TIMEOUT`, `VM_EXECUTION_FAILED`, mapping-probe failures and `WORKSPACE_MAPPING_MISMATCH` in structured tool results.
- Stop context-budget archive markers from embedding stale tool-result tails. Historical assistant excerpts and recalled tool results are explicitly labelled as non-authoritative/current-state snapshots.
- Add mapping/lifecycle/error evidence to diagnostics, plus regression coverage for stale-compaction text, temporary-probe cleanup, mapping mismatch, Git cleanliness, history epistemic labels and lifecycle generation.

## v0.3.4

- Add **live oMLX TPS** while a model call is in progress. Detected/explicit oMLX requests now poll the server's lightweight `/admin/api/activity` surface in parallel with `/v1/chat/completions`, using the server's current per-request `tokens_per_second` for decode and prefill tracker speed where available. The final OpenAI-compatible usage chunk remains the authoritative completed-call metric.
- Authenticate the oMLX activity poll correctly. Current oMLX protects `/admin/api/activity` with an admin-session cookie, so HarnessyXO performs `/admin/api/login` with the profile API key when needed and reuses the returned cookie only inside the telemetry HTTP client. An optional **oMLX admin API key** profile field is available for installations where the model API uses a sub-key; oMLX intentionally does not permit sub-keys to create admin sessions.
- Treat oMLX activity telemetry as strictly best-effort: missing/older endpoints, failed admin login, ambiguous concurrent requests, or model aliases that cannot be safely matched do not affect generation. In those cases HarnessyXO continues to show the final native usage TPS when the call ends instead of inventing a stream-arrival rate.
- Clarify the model setting label as **Read local Ollama progress logs for live TPS (Ollama only)** so it is not confused with oMLX telemetry. Preserve v0.3.3 whitespace-card handling and all earlier v0.3.x behavior.

## v0.3.3

- Fix blank **HarnessyXO** answer cards created by whitespace-only assistant deltas around tool calls. Visibility is now based on rendered-text semantics (`strip()`), across live answer/reasoning updates, persisted stream grouping, reload rendering, timing labels, and model-step completion state. Leading whitespace is still preserved if real answer text arrives later.
- Add first-class **oMLX** backend detection and an explicit oMLX API-mode option while retaining the OpenAI-compatible chat transport. Auto mode recognizes current oMLX model listings via `owned_by: omlx`.
- Force `stream_options.include_usage=true` for detected/explicit oMLX even when an older generic profile has streaming usage disabled, and normalize oMLX's native `generation_tokens_per_second` / `prompt_tokens_per_second` plus timing durations. Persist the native decode/prefill rates and provenance into Stats instead of falling back to character/chunk timing.
- Preserve v0.3.0 strict-system-message + llama.cpp TPS behavior, v0.3.1 File Explorer columns, and v0.3.2 chat/RE-tool additions.

## v0.3.2

- Prevent very long unbroken live Tool/Thinking/status text from widening or painting outside message cards. Constrain the transient tool-generation row, ellipsize its tail label, clip card ownership boundaries, and keep raw/code blocks internally scrollable.
- Add **Go to top** to each chat `…` menu. Jump directly to the earliest bounded transcript window, set the reader at the first message, preserve the database, and retain the existing direct Jump to latest path.
- Expand the Ubuntu Reverse VM package set with additional debugger, binary, firmware, Android/JADX/DEX, forensics, carving, LLVM, emulation, UPX/PE/.NET, multiarch and dynamic-analysis utilities on a best-effort basis. Add isolated guest environments for angr 9.3.4, capa 9.4.0, FLOSS 3.1.1, LIEF/r2pipe/Keystone/Capstone/Unicorn and PE/ELF/.NET/Mach-O parsing, firmware filesystem readers (`ubi-reader`, `jefferson`), and Frida CLI tooling so their dependencies cannot affect system Python.
- Provision the official pinned Ghidra 12.1.3 release with JDK 21 and SHA-256 verification; expose `ghidra-headless` and `ghidra`. Attempt upstream `buildNatives` on Linux ARM64; use upstream prebuilt Linux natives on x86_64.
- Tell the workspace agent about the reverse preset and how to invoke its binaries through the existing VM shell/process tools. Preserve the no-silent-upgrade policy: existing persistent VMs require an explicit Rebuild VM to receive a changed tool preset.
- Preserve v0.3.0 system-message/llama.cpp TPS behavior and v0.3.1 File Explorer columns/sorting.

## v0.3.1

- Replace the File Explorer's separate Sort by dropdown/direction toolbar with CloudCmd-style clickable column headers: **Name, Size, Date modified, Type**.
- Clicking a different header selects that sort key in ascending order; clicking the active header reverses direction and shows an ↑/↓ indicator. Preserve the existing persisted global File Explorer sort state and folders-first behavior.
- Align parent, folder and file rows to the same column grid. Show file size, modification time and type/extension; show folder/parent metadata without recursive folder-size calculation.
- Keep the header above the scrolling listing and use container-responsive column collapse on narrow panes. Remove the old sort dropdown, order button and hint UI completely.
- Preserve v0.3.0 model/request/TPS behavior and all File Explorer operations outside presentation/sorting controls.

## v0.3.0

- Restart the release line from the exact v0.2.44 baseline; do not carry forward v0.2.45–v0.2.59 application changes.
- Keep long-chat archive guidance and automatic-continuation guidance inside one leading system role. Add a transport-level invariant that folds every system-role fragment into that first message before either OpenAI-compatible or native Ollama transport, fixing strict llama.cpp/Jinja templates that require the system message to be first.
- Add explicit and auto-detected llama.cpp backend handling while retaining its OpenAI-compatible `/v1/chat/completions` transport. Request llama.cpp per-token timings, normalize only documented numeric timing counters, and surface native decode TPS (`predicted_per_second`) during generation.
- Persist llama.cpp prompt/decode rates, native token counters and backend timing durations into per-call generation metrics. Prefer native llama.cpp and Ollama timing counters over stream-arrival fallbacks and record the throughput provenance in Stats.
- Add Settings help for the llama.cpp API mode plus regression tests for strict system ordering, llama.cpp auto detection, timing parsing/streaming, and native timing persistence. Preserve v0.2.44 behavior outside these changes.

## v0.2.44

**Fix compressed web responses (DecodingError)**

The shared Web Search / Open / Download fetcher no longer decompresses HTTP response bodies twice. HTTPX already decodes Content-Encoding while streaming; the detached response now receives a copy of the headers without the stale Content-Encoding, compressed Content-Length or Transfer-Encoding. Its length is calculated from the decoded body. Content type, charset, download filename and other metadata are preserved. This also prevents an HTTP-compressed archive from being silently unpacked an extra time.

The existing byte limit is still enforced on **decoded bytes**. Redirect validation, private-network restrictions, timeouts, cancellation, private source caching and artifact storage remain in place. Genuine decoder failures return a request-specific error (host, HTTP status and encoding), not a conclusion that all web access is broken; failed content is not cached or saved. No automatic retry, permission bypass or new dependency is added. Compression support continues to follow the installed HTTPX codecs.

The first-request web tools, current-information instructions and **Off / Ask / On** permissions are unchanged. Cached Find still operates without another network request or approval. Existing Settings, chat Thinking choices, models and VMs are untouched. This narrow fix does **not** include the pending File Explorer clickable-column-header redesign.

Install into a new application folder, stop only the instance being replaced, retain its `.settings/` and external workspaces, then run `python3 run.py` and use the fresh launch URL. No settings deletion, chat reset, model rebuild or VM rebuild is required. See **VERIFICATION_v0.2.44.md** for reproduction, tests and limitations.

## v0.2.43

**Visible File Explorer sorting**

Home and workspace File Explorers now have a dedicated **Sort by** row directly below the path/actions and above the scrolling file list. Choose **Name, Date modified, Size or Type**. The neighbouring button states the current order in words (**A → Z / Z → A**, **Oldest first / Newest first**, or **Smallest first / Largest first**) and clicking it reverses that order. Folders stay first; Type uses the file extension, and Size does not calculate recursive folder totals.

The sorting row does not shrink away or scroll off with the files. Its controls and the navigation actions wrap within narrow panes. The existing saved sorting preference is reused and shared by Home/workspace explorers, including after navigation, tab changes, page reload or application restart. Sorting remains available in empty and unreadable directories. Late events from a closed/background explorer cannot redraw a different active chat.

This is a narrow File Explorer UI correction on **v0.2.42**. Thinking/default verification, models, web access, agents, snapshots, file-operation permissions and all other features are unchanged. No settings reset, VM rebuild or new dependency is required. See **VERIFICATION_v0.2.43.md** for executed tests and native-framework limitations.

## v0.2.42

- Correct the native verifier to read Ollama's `_debug_info` envelope; retain compatible unprefixed responses without accepting malformed or contradictory proof. Correct the shared test double and add independent API-contract regressions.
- Make Default an unconditional omission rather than silently inheriting the old profile Medium. Preserve explicit chat selections and retain saved profile values as an opt-in profile preset. Do not erase or infer authorship of existing profile/chat values.
- Display Qwen3.8's highest level as xhigh in the composer, Settings, Thinking headers, verification summaries and recorded Stats. Keep stable saved keys and transport-specific mappings; do not send native xhigh blindly or relabel unrelated models.
- Keep installed-endpoint default evidence separate from stock-template defaults, explain possible server fallback differences, and stop inferring server age from failed proof or version 0.0.0. Preserve no-extra-probe Default/Off behavior, cancellation, metadata checks and Save/Cancel.
- Add real-envelope positive/negative tests, default/profile/explicit separation, old-Medium request omission, persistence, independent-chat, display and actual payload regressions. Prior release tests are retained, with only superseded expectations updated.

## v0.2.41

- Display a verified backend Thinking default as Default · High/Medium/Low/Off, with the observed effort, timestamp and no-override explanation in the tooltip. Keep Model default for unknown endpoints; preserve configured profile defaults and per-chat Default/explicit intent.
- Extend the confirmed native renderer check to test omitted Thinking parameters, separate default-display evidence from explicit wire mappings, and compare an unmarked default against a verified Medium reference rather than guessing. No extra probes on ordinary Default/Off sends or reloads.
- Scope persisted default observations to model/endpoint/credentials/server version and metadata (including system and messages); invalidate stale evidence and reject stale asynchronous writes. Keep checks bounded, cancellable and protected by existing scheduling.
- Show recorded default evidence in Stats, refresh just the composer control on metadata changes, and update selection tooltips without rebuilding the composer. Fix the model-settings Thinking preset import collision with VM presets.
- Add default-proof, payload-omission, cache/invalidation, UI/save/reload, cancellation and diagnostics regression tests. Preserve the existing maintained suite and document native-server limits separately from synthetic tests.

## v0.2.40

- Separate untouched/default Thinking from an explicit per-chat choice. New profiles omit a Thinking override by default; preserve saved profile defaults, credentials and existing chat choices. Save explicit model/Thinking selections immediately and restore them after page/application reload without resetting them on a model switch.
- Add a model/transport-aware Thinking control layer, Qwen3.8-compatible High → xhigh, configurable compatible Off mechanisms and safe binary fallback for newly detected unknown thinking models. Preserve existing expert-configured generic compatibility through a non-destructive legacy preset.
- Detect native Ollama capabilities automatically via metadata, including custom Qwen3.8 tags whose architecture says qwen3_5. Repair stale disabled API mode after positive capability detection. Refresh the composer selector without replacing the draft/transcript; reject stale detection writes.
- Verify native Qwen3.8 levels against installed /api/chat renderer output, not guessed high/max strings or HTTP status alone. Bound older-server fallback, permit cancellation, scope/cache proofs, preserve scheduling and expose manual confirmation/report and explicit custom mappings.
- Record raw/effective/source/wire Thinking diagnostics. Keep all v0.2.39 web, activity, snapshot, timing and tool/VM changes intact. Add failure-first regression tests and document limits separately from synthetic test passes.

## v0.2.39

- Complete the eight feedback items: consistent workspace-create icon, owned-work tab spinners and selected-pane favicon, persistent explorer sorting, verified/reconciled snapshots, compact expandable queued follow-ups, explicit observed per-phase/tool-execution timing and engine/profile labels.
- Directly expose Search/Open/Find on the first model call under Web Ask/On; preserve Ask/Off enforcement and specialized Download discovery. Strengthen current-information guidance, retain optional Web Research and unchanged browser automation.
- Keep stream chronology and old history intact; never relabel legacy total times as phase durations. Exclude approval/writer waits from actual tool execution timing. Surface provider listing failures rather than fake empty snapshot lists; reject stale cache writes after verification.
- Add behavioral and production-renderer/browser regression coverage alongside the existing maintained checks. Verification documents native framework/model/VM limits explicitly.

## v0.2.38

- Flatten Agent/Tools Settings into one compact tab row while preserving staged Save/Cancel and Global/Workspace instruction scopes.
- Vertically centre one-line Thinking/Tool tails without increasing row height or changing transcript/follow logic.
- Remove the visible Skill picker; force new sends to Auto without changing saved historical content or tool permissions.
- Add 36 task templates (40 total defaults), nine categories, search, full preview, explicit captured-chat insertion and editable category/description fields. Schema 9 migrates once, preserving custom text/order/metadata and respecting later deletions.
- Use 16 px chat/archive/tab icons and a neutral outline project/tree workspace icon. Double-click opens/focuses the clicked Environment tab across single-click row remounts; retain selection/dragging/menus.
- Pin browser/backend health beneath the sidebar. Browser state follows actual socket events; backend checks mean server reachability, with cached-state indication during disconnection, bounded/profile-scoped probes and redacted endpoint details.
- Replace the wordy footer with activity/fresh TPS/run elapsed/context and a separately reserved Stats hitbox. Distinguish Last metrics and measured/estimated context; hide secondary fields by container width. Keep expanded diagnostics in a scrollable details dialog; do not call unknown pricing Local.
- Fix the fluent tooltip-return alias that overwrote the context label with its explanatory paragraph. Reject unrelated model context in Ollama /api/ps fallback.
- Add behavioral migration/editor/runtime/health tests and production-CSS/browser-JS geometry tests. Fix template list flex-shrink overflow found during visual inspection. Native framework and real-machine limitations are reported, not counted as passes.

## v0.2.37

### Browser authentication hotfix

- Fix the v0.2.36 launch failure displaying “HarnessyXO access token was rejected.” The branding change renamed the JavaScript request header while the server still checked the stable internal header.
- Generate the browser header from the same `ACCESS_HEADER` constant the server uses. Keep the `harnessy_access` cookie and `/__harnessy_auth` endpoint unchanged; do not weaken authentication or change user data.
- Add regression coverage that reads the served HTML and executes its exact JavaScript against the production middleware. Native-browser network tests remain separate and explicitly skip when Chromium policy blocks navigation; bridge tests are not reported as native end-to-end passes.
- All other application behavior remains v0.2.36. See `VERIFICATION_v0.2.37.md` for checks and limits.

## v0.2.36

- Display branding HarnessyXO and actual sidebar version; neutral outline workspace folders and chat/archive icons. Internal storage, IDs, launchers and historical message text stay compatible.
- One-line latest-tail Thinking/Tool previews, coherent scroll geometry bookkeeping, input-owned follow release/rearm and activity after visible output. Live-view adoption/retention across persistence, paging and reattachment, with transient-to-canonical anchor aliases.
- Whole-request budgeting with runtime recheck, schema/output reservation, same-turn completed-step compaction, original-source retrieval and bounded memory prompt excerpts. Label estimates separately from measured usage; use actual guest architecture in core instructions.
- Approved absent-only Global Instructions default, confirmed staged restoration, and ten workspace instruction templates with preview, explicit Use/Replace/Append/Cancel and Save-only persistence.
- Atomic changed-memory writes, durable model/manual origins, confirmed deduplicated inline Memory updated / View notices and read_project_memory retrieval.
- Editable public outbound policy for existing VMs using reserved stop/apply/start, active-work exclusion, stale-editor checks and verified failure rollback without disk/Files deletion.
- Shared selected-backend host prerequisites for launcher and Create/Start, PATH repair, package progress/verification, compatibility and no-upgrade/active-infrastructure safeguards.
- Additional failure-first browser, storage, request-budget, memory, host-installation and VM-policy regressions. Native framework/VM availability limits remain explicitly reported.

## v0.2.35

Follow intent, full-height editors, environment catalog, Markdown exports

- Fixed delayed native-scrollbar release ordering; retained browser-owned Jump state, virtual window bounds and user-pause protections.
- Replaced Performance QBtn with one native/SVG control, aligning glyph, hover/focus and clickable area.
- Full-height text editor; sanitized Markdown Preview/Edit; encoding/newline preservation and external-change detection.
- Compact template rows with dedicated staged Apply editor; consistent Settings titles/descriptions.
- Separate guest image/architecture/tool catalog, immediate read-only preview, unchanged existing-environment reuse. Added experimental Debian 12, Fedora 43 and x86-64 QEMU paths; apt/DNF adapters and Debian/QEMU mount compatibility. Kept Ubuntu RE ARM64 default. OpenWrt/Windows/Pi remain future integrations.
- Five Markdown export levels, disk-backed SQLite snapshots and bounded streaming; deterministic activity counts; scheduler-coordinated, tool-free hierarchical summaries; record ranges, metadata, optional attachment ZIP, cancellation and persistent finished artifacts. Original conversation history is not rewritten.
- Added native Chromium scrollbar/geometry tests, production callback editor tests, 18 image/tool/architecture configuration cases, and backend export/FIFO/attachment regressions. Native NiceGUI and actual VM boots are separately identified, not simulated as passed.


## v0.2.34

- Preserve the v0.2.33 virtual transcript and viewport structure. Rearm following after deliberate downward navigation reaches the real latest page, including a wheel/End gesture at an already clamped bottom. Do not let ordinary page completion or a disclosure/resize clamp silently disarm it.
- Make Jump to Latest visibility browser-owned outside NiceGUI's reactive element styles. Keep it visible while away from the real tail or waiting for a latest-page transaction; retain pending clicks and let upward input override follow.
- Remove the non-functional green Performance badge. Disable Quasar ripple using an actual Boolean property and retain subtle hover, keyboard focus and the Performance action.
- Read fresh Ollama progress-log telemetry independently of HTTP status, using bounded read-only host I/O. Preserve live/average/counter-delta provenance, reject stale or ambiguous samples, pass timestamps through owner/reattached UI, and replace endless “measuring” with an explicit unavailable state. Add per-model log enable/path controls. Unlabelled external-client concurrency remains a documented attribution limitation.
- Keep only Global Instructions in global Settings. Add a workspace-menu Instructions dialog bound to the clicked workspace with independent Save/Cancel, existing-content preservation and an external-change conflict check.
- Stretch Workspace Memory and Workspace Instructions through the entire QField/native-textarea height chain; keep long text internally scrollable and controls visible. Preserve memory Save/Reload and all storage/prompt semantics.
- Extend protocol, parser, production-callback, Chromium scroll/geometry and scope regression tests. Full native NiceGUI remains a separately reported test, not a simulated pass.

## v0.2.33

- Correct the definite-height owner for the complete NiceGUI/Quasar page hierarchy. A percent-height shell beneath auto-height/min-height-only wrappers could collapse the transcript viewport to zero even with messages loaded. Use `100vh` with `100dvh` enhancement on the shell, rather than depending on an unresolved percentage chain. Keep the composer and status footer in separate normal-flow flex rows.
- Rebuild bounded history rendering on one canonical transcript container. Read the newest 48 durable records initially, shift by 24 records, and retain no more than 72 durable records per window. Reuse overlapping native rows; delete off-window UI elements, never stored messages. Thinking and raw tool bodies render only when expanded.
- Add generation-scoped read-only paging transactions with visual-anchor restoration after DOM layout. Handle absolute-top paging, resize-induced scroll clamping, direct Jump to Latest, and a Jump clicked while a history update is pending. Window acknowledgements resolve after the browser restoration, rather than before it.
- Fold completed live model/tool/follow-up events into bounded history every 12 persistence events. Retain the current live step, carry open disclosures into durable rows, freeze a paused reader's window, and reconstruct process-owned live state when returning to the tail or rebuilding a page.
- Bound the entire client JavaScript wait, including NiceGUI's connection wait, so a disconnected browser cannot indefinitely hold a runner's compaction/cleanup boundary.
- Reconcile queued follow-ups by identity and text, not only length: both N-to-0 and A-to-B with unchanged queue count redraw correctly.
- Keep current rows on a paging read failure and show an explicit notice. An initial render failure also displays an error instead of silently leaving an empty panel. No database deletion, history truncation, or schema migration is added.
- Add production-renderer/SQLite/Chromium integration coverage, mixed-height saved-history fixtures, a 42-step simulated live runner, paging read-only tests, and a separately reported optional native NiceGUI server test. The native test is not treated as passed when its runtime is unavailable.

## v0.2.32

- Emergency recovery release: completely removed the v0.2.30-v0.2.31 transcript virtualization/windowing renderer and restored the known-visible v0.2.29 full-history transcript path.
- No transcript paging helpers, virtual sentinels, bounded-window render state, or live-history compaction are used in the browser rendering path.
- Kept the independent queued-follow-up reconciliation fix so a consumed queue transition from N to 0 clears the stale queued card above the composer.
- No chat-message delete/update migration is introduced by this recovery release.

## v0.2.29
- Fix the real v0.2.28 transcript/composer overlap after reproducing it with NiceGUI's actual container CSS. The missing interaction was `ui.column`'s `.nicegui-column { align-items:flex-start }`: v0.2.28 changed that same node to CSS Grid but never reset alignment, so the transcript grid item kept max-content height and painted straight through the composer. The chat owner is now an explicit stretched flex column, and the transcript scroll element is absolute-filled inside a flex-owned transcript region with paint containment, so long user/assistant/tool content cannot affect outer bottom geometry or render behind the composer.
- Reset NiceGUI's default `.nicegui-content` 1rem padding/gap for Harnessy's full-viewport shell. The old `100vh` shell was effectively 32px taller than the visible content box, which clipped the real bottom footer. Harnessy now owns the exact content box height end-to-end.
- Rework the status footer as a normal opaque non-scrolling row: remove its horizontal scrollbar, keep the monitor control anchored, and hide lower-priority cache/message/prefill/average labels responsively on narrower windows while preserving full metrics in Performance. Composer and status surfaces now form a visual paint barrier as well as a layout boundary.
- Fix ghost **Stop** state after cancellation/completion. Final cleanup hides Stop whenever the affected chat is selected even if its transcript element was rebuilt, and the existing 0.5 s lightweight UI timer reconciles the active composer from the authoritative process-owned agent task so reconnect/page-detach races self-heal automatically.
- Replace the misleading v0.2.28 browser fixture with a NiceGUI-aware Chromium regression that includes the framework's real root padding and `ui.column` alignment rules. The test reproduces the prior overlap, verifies transcript/composer/status physical boundaries at a 1032×807 viewport, checks that transcript paint is clipped behind the composer, exercises composer growth/follow/Jump-to-Latest/scrollbar-drag behavior, and confirms the status row has no horizontal scrollbar. Full suite remains 205 tests. VM/environment, reconnect ownership, scheduler, writer leases, diagnostics architecture and instruction prompt plumbing are otherwise unchanged from v0.2.28.

## v0.2.28
- Rebuild the bottom-of-chat geometry around one explicit three-row owner: **transcript / composer / status bar**. The transcript is the only vertically scrolling row; composer and footer remain in normal grid flow, so live assistant/tool/thinking content cannot extend behind them. **Jump to latest** is now an absolute transcript-shell overlay and no longer changes the available transcript height merely by appearing or disappearing.
- Fix follow ownership instead of adding another scroll-padding/timer patch. The browser-local follower now observes the transcript viewport itself as well as transcript growth, so composer autogrow, attachments, queued follow-ups, footer changes and browser resizes all reconcile the true visible bottom. Programmatic-scroll suppression is target-aware instead of a blanket time window, so an intentional scrollbar/pointer drag during a recent auto-pin immediately wins and pauses following rather than being yanked back down.
- Anchor the Performance monitor indicator to the same fixed-size positioning wrapper as the actual monitor button in every closed/open/hover state, while keeping the popup independent from indicator geometry and free of an internal tooltip scrollbar.
- Prefer Ollama `live_tps`, then `avg_tps`, before compatible legacy/direct TPS aliases; preserve generated-token/elapsed sampling as the live fallback so long-running generation does not remain stuck at `measuring tok/s...` when telemetry is available.
- Add separate **Global Instructions** and **Workspace Instructions** editors under Settings → Agent / Tools → Agent → Instructions. They persist as `.settings/GLOBAL_INSTRUCTIONS.md` and `<workspace>/.LLM/WORKSPACE_INSTRUCTIONS.md`, remain separate from `PROJECT_MEMORY.md`, omit empty prompt sections, and are injected in the documented order: Harnessy core → Global → Workspace → selected Skill → Project Memory → conversation. Opening/reading prompt context does not create machine state, and saving unrelated settings does not silently rewrite unchanged user-authored instruction files.
- Add a real headless-Chromium regression for bottom geometry/follow behavior in addition to source-level guards. It exercises composer-height changes, paused Jump-to-Latest geometry, transcript growth, intentional scrollbar drag during the programmatic-scroll guard, and monitor-dot placement. Expand the full regression suite to 205 tests. Reconnect/diagnostics, model scheduler, writer coordination, VM/environment lifecycle and no-host-fallback behavior are otherwise left unchanged from v0.2.27.

## v0.2.27
- Fix the repeated NiceGUI reconnect/reload amplification seen on long chats. A newly reattached page no longer redraws the already-rendered persisted transcript a second time before attaching the transient live agent segment; this removes a large duplicate websocket/DOM burst on 400+ message conversations. Live reattachment polling is relaxed to 0.5 s and server-driven phase-clock updates to 1 Hz, reducing transport chatter without changing backend generation cadence.
- Persist browser socket-drop metadata through NiceGUI full-page recovery via `sessionStorage`, so reconnect duration/reason/attempt telemetry survives the reload that previously erased it. Add a process-level event-loop stall watchdog plus page-build IDs to make any remaining transport stall directly diagnosable.
- Fix the unsafe Ollama context fallback exposed by the reconnect diagnostics: when no already-loaded runner context can be discovered, Harnessy no longer turns an old 1,048,576-token profile cap into an actual 1M `num_ctx`. Unknown runtime state now starts at a conservative 262,144-token ceiling (or a smaller profile cap); an explicitly observed larger Ollama runtime remains respected. New model profiles also default to 262,144, and the legacy factory-default 1M profile value migrates to 262,144 on upgrade so an already-loaded 1M runner cannot silently carry the accidental setting forward.
- Make diagnostics ZIP creation strictly on-demand. Ordinary logging, startup, shutdown, agent failures, VM failures and launcher activity never regenerate the ZIP in the background. **Download Diagnostics** snapshots current raw logs on a worker only when clicked, and Harnessy installs `.logs/collect_diagnostics.py` so the same latest bundle can be collected from Terminal even when the GUI is inaccessible. The stale ZIP from a previous process is removed on startup to avoid confusing old evidence with the current session.
- Move the header **Download Diagnostics** bug icon to the right of **Settings** as requested.
- Expand regression coverage to 200 tests, including on-demand diagnostics collection, the recovery collector, unknown-runtime 262k context safety, reconnect amplification guards, socket-drop persistence and header action ordering.

## v0.2.26
- Hotfix the v0.2.25 composer deadlock. Restoring **Stop generation** and the generation UI busy-state helper fixes the first-Send exception that could leave a chat marked busy with no live agent consumer.
- Make process-owned agent task state authoritative for Send/queue decisions. Stale `busy_tabs`/page-local markers are reconciled away instead of turning an ordinary message into a ghost queued follow-up.
- Add automatic orphan-follow-up recovery: if a queued steering message exists but no backend agent is alive to drain it, Harnessy promotes the oldest queued message into the next normal turn rather than leaving the composer stuck.
- Rename workspace sidebar headings to **CHATS [workspace]** and **ARCHIVES [workspace]**.
- Preserve v0.2.25 scroll/reconnect/sidebar behavior and v0.2.24 model scheduling/writer coordination unchanged.

## v0.2.25
- Rebuild chat following around one event-driven browser-local controller. Remove the 80 ms follower polling loop and live scroll-state websocket emissions; one fixed-wrapper `ResizeObserver` schedules a single animation-frame pin only when streamed layout actually grows. Upward user intent pauses immediately, returning to the bottom resumes follow, paused reading uses native scroll anchoring, and **Jump to latest** performs one bounded settle then relies on the same growth observer.
- Reduce reconnect pressure and make intermittent NiceGUI reconnects diagnosable. Chat scroll position is authoritative in browser `localStorage` during active use instead of sending a server event after scroll corrections, successful websocket reconnections log bounded outage duration/reason/attempt metadata, periodic diagnostics-ZIP refreshes now run off the NiceGUI event loop, and the backend protocol tail appends incrementally instead of synchronously rewriting the entire growing ring file on every decoder event.
- Add a clear divider above Archives and shorten workspace-specific sidebar headings to **CHATS <workspace>** / **ARCHIVES <workspace>** while preserving independent collapse state and Archives-collapsed-by-default behavior.
- Remove **Interrupt & Send**. Sending while an agent is active always queues steering for the next safe boundary; **Stop** is the sole explicit way to interrupt before sending a new instruction.
- Fix themed action-menu horizontal overflow by giving the menu and buttons explicit border-box sizing/min-width rules and hiding accidental x-overflow.
- Extend chat drag-and-drop across the Chats/Archives boundary. Dragging onto either list reorders in real time; dropping on the opposite list or even its collapsed section header archives/unarchives the chat and persists destination ordering. Busy chats cannot be moved across the lifecycle boundary until stopped.
- Preserve v0.2.24 model scheduling/writer coordination/live TPS and v0.2.23 coalesced streaming performance while expanding regression coverage for the new scroll, reconnect, menu and archive-drag behavior.

## v0.2.24
- Add first-class chat lifecycle controls in the sidebar. Every active chat now has a themed icon `…` menu for **Rename / Archive / Delete**; archived chats keep their full history and expose **Unarchive / Rename / Delete** in a separate `<workspace>'s ARCHIVES` section.
- Make **WORKSPACES**, `<workspace>'s CHATS`, and `<workspace>'s ARCHIVES` independently collapsible. Archives are collapsed by default on initial load and whenever a different workspace is selected.
- Consolidate the selected-workspace action strip into one consistent icon menu for Terminal, Environment, Workspace Memory, File Explorer, ZIP / Downloads and the visually separated destructive Remove Workspace action. The ellipsis trigger no longer leaves a redundant tooltip floating over an open menu.
- Add native-feeling main-tab drag reordering. Tabs move in real time under the pointer, the active tab remains active, accidental post-drag clicks are suppressed, and the resulting order persists across browser reloads/Harnessy restarts through the existing UI-session state.
- Repair bottom-status polish: Performance/context tooltips opt out of internal scrolling, and the green monitor indicator is absolutely anchored to the monitor icon wrapper so opening the details control cannot push the dot to the right.
- Drive sidebar chat activity spinners from the real process-owned agent task state on the existing lightweight timer. Completed/failed/cancelled chats return to idle without waiting for a sidebar rebuild, eliminating ghost spinning after the Stop button disappears.
- Add queued steering for long-running agents. The composer remains usable while a chat is busy; normal Send stores an ordered **Queued follow-up** and injects it only at a safe model/tool boundary. **Interrupt & Send** is the explicit immediate path. Final-boundary intake is closed atomically so a message sent while the old run is unwinding cannot be stranded.
- Add a process-wide FIFO model-generation scheduler. **Concurrent model generations** defaults to `1` (configurable 1–8) so independent chats can overlap VM/tool work without unexpectedly allocating several huge model contexts/KV caches at once; waiting chats surface the current model owner instead of looking hung.
- Surface **live decode speed during Generating**. Native Ollama telemetry is sampled independently from decoder chunks (so a healthy continuous stream cannot starve status updates), accepts direct TPS or standard `eval_count`/`eval_duration` metrics, smooths counter-derived live samples, and shows `Generating · 25.4 tok/s · …` on both the originating and reattached chat UI.
- Add workspace writer coordination across independent chats. Read-only tools remain concurrent, while the first potentially mutating filesystem/shell/process/Git/workspace-memory action in an agent run acquires a sticky per-workspace writer lease until that run finishes/cancels/fails. Direct toolbox calls use bounded per-call leases so utility callers cannot leak ownership.
- Preserve v0.2.23's coalesced live Markdown renderer, constant-cost chat-follow loop, v0.2.22 continuation/tool-activity handling, and the VM-first/no-host-fallback security architecture.
- Expand regression coverage to 193 tests, including archive ordering, scheduler concurrency, writer serialization/sticky ownership, safe queued-follow-up continuation, sidebar/menu/tab/status/spinner source guards, and settings migration to the new concurrency default.

## v0.2.23
- Fix progressive browser-side live-stream slowdown during long agent runs. The originating chat page no longer reparses/replaces the full accumulated Markdown body for every decoder chunk; backend text still accumulates losslessly at Ollama speed while visible Markdown updates are coalesced to a bounded cadence, with adaptive throttling for exceptionally large single turns and forced final flushes at model/tool boundaries. This makes the original live page use the same batching principle that previously made an F5/re-attached page appear fast again.
- Remove per-token server→browser scroll RPCs from live answer/reasoning callbacks and from the reattachment synchronizer. Streaming no longer queues a JavaScript round-trip behind every decoder fragment.
- Replace transcript-wide MutationObserver/per-child ResizeObserver bottom pinning with one constant-cost browser-local follower. While follow mode is active it only compares the scroll container's `scrollHeight` and bottom distance every 80 ms, so the amount of scroll work no longer grows with transcript size.
- Keep smart follow semantics explicit: any upward user gesture pauses immediately, returning to the real bottom re-arms follow, and **Jump to latest** forces the actual bottom then remains pinned through later Markdown/code-block growth. Programmatic follow scrolling is excluded from persisted user-scroll events so continuous generation does not create a new stream of scroll-state RPCs.
- Preserve v0.2.22 agent-continuity/output-limit handling, live tool-construction activity, v0.2.21 reattachment, and the VM-first execution/security model unchanged.
- Restore the portable root `run_harnessy.sh` launcher in the release archive; it simply enters the Harnessy folder and executes `python3 run.py` while preserving command-line arguments.
- Expand regression coverage to 186 tests, including checks that token/reasoning callbacks cannot call Markdown `set_content()` or scroll RPCs directly, model/tool boundaries force the final coalesced paint, live-sync performs no scroll JavaScript RPC, and chat following no longer installs transcript-subtree observers.

## v0.2.22
- Remove the premature blank **Harnessy** answer card from tool/reasoning-only model steps. The answer card stays hidden until real assistant answer/error/cancel text exists; model activity uses its own lightweight row instead.
- Make otherwise-silent tool-call construction observable. Harnessy now consumes live Ollama runtime telemetry, shows Prompt Processing/Prefill/Generating progress and generated-token counts, and surfaces safe partial tool-call identity/target information such as **Generating Tool · write_file · README.md** without echoing large file payloads.
- Replace one-shot chat scrolling with bottom pinning. Follow mode is maintained through streamed Markdown/layout growth via mutation/resize observers, still disengages immediately when the user scrolls upward, re-engages at the bottom, and **Jump to latest** performs settling passes so it reaches the actual final bottom instead of stopping short.
- Treat an Ollama transport EOF before the required final `done:true` event as an explicit backend failure rather than a clean model finish. Inspect backend `done_reason`/`finish_reason` on every step and reject unknown abnormal terminal reasons.
- Make the per-inference output ceiling non-terminal for long agents. `done_reason=length`/equivalent output-limit reasons automatically continue the same agent run with a fresh generation budget; any possibly truncated partial tool call is discarded rather than executed and must be regenerated on the continuation turn.
- Recover reasoning-only/empty nominal model finishes with a bounded automatic continuation instead of silently declaring the whole agent done, while persisting explicit terminal/continuation reasons in message metadata and diagnostics.
- Preserve a bounded structured tail of the immediately previous Harnessy session inside `Harnessy-Diagnostics-Latest.zip`, so restarting Harnessy no longer erases the final backend/runner events needed to diagnose a mysterious prior stop. Previous-session console capture is intentionally excluded.
- Reinforce the agent system prompt that the per-turn output budget is finite but the overall agent run is not, encouraging large builds to proceed incrementally across tool calls/turns instead of attempting one enormous response.
- Expand regression coverage to 185 tests for incomplete Ollama EOF, output-limit continuation, truncated-tool safety, reasoning-only recovery, abnormal finish reasons, tool-construction activity, blank answer-card suppression, robust bottom pinning, and previous-session diagnostic tails.

## v0.2.21
- Repair live transcript streaming after the v0.2.19 lifecycle hardening. Active agent presentation state is now process-owned per chat, and a newly rendered transcript/browser page can reattach to the same still-running backend job instead of remaining visually frozen until a manual reload. Completed model/tool records are reconciled from the workspace DB while the current in-flight reasoning/answer/tool segment is rendered from the live snapshot.
- Keep the original low-latency streaming callbacks while they are valid, but hand presentation over automatically when their exact transcript generation is replaced/deleted/inactive. The reattachment observer is page-owned, non-overlapping, guarded against stale NiceGUI lifecycles, and never owns or cancels the backend agent run.
- Make silent post-tool inference observable. Prompt Processing, Prefill, Generating and Waiting phases remain visible with live elapsed time even before the model emits reasoning, answer text, or its next tool call, including after a chat reattachment.
- Restore smart chat follow behavior: upward user scrolling pauses follow immediately; reaching the bottom re-enables follow automatically, including the browser edge case where the final downward wheel/key gesture is clamped at the bottom and produces no additional scroll event. Streaming never re-enables a deliberately paused view by itself.
- Persist each chat's model/thinking/skill runtime selection in workspace state. Thinking level therefore survives transcript reconstruction, browser refreshes and Harnessy restarts instead of reverting to the model default.
- Correct context-window terminology. The status bar and metrics now distinguish the active/effective Ollama runtime context from the Harnessy model-profile context cap, show the cap as an exact token count, and request diagnostics report `context_window_profile_cap` plus `context_window_effective` instead of calling the profile cap “Configured”. Harnessy continues to clamp Ollama requests to the observed active runtime rather than enlarging it.
- Rework Settings into a fixed header/footer shell with an explicitly scrollable content pane and visible scrollbar. Remove the empty Chat placeholder subtabs, move the actual Enter-to-send setting into Chat, collapse template editors by default, and split the long Agent / Tools page into Agent and Tool Permissions subtabs.
- Expand regression coverage to 178 tests for live-agent reattachment, silent phases/tool state, smart follow re-engagement, thinking persistence, context wording/telemetry, Settings scrolling and compact Chat/Agent settings UX.

## v0.2.20
- Remove the Reverse Engineering/Development package installer from Lima's per-boot `provision:` list. Ordinary workspace **Stop → Start** now boots the existing persistent VM disk without running `apt-get update` or reinstalling the preset toolchain.
- Add explicit one-time preset provisioning after Create/Rebuild/Factory Reset. Required packages are checked first, only missing required packages are installed, optional tools remain best-effort, and a guest `/var/lib/harnessy/provisioning.json` marker records completion.
- Migrate existing v0.2.19-and-older workspace VMs in place. The stopped Lima instance is edited once with `.provision=[]`; if the existing disk already contains all required preset packages, Harnessy adopts it and writes the new marker without one last package-manager cycle.
- Preserve the verified-running fast path: opening additional terminals/tools against the same Ready VM does not rerun provisioning or even perform an unnecessary provisioning-marker check.
- Keep first-time/rebuild/reset setup observable with dedicated **Checking workspace tools / Updating package index / Installing required tools / Installing optional tools / Finalizing** progress stages while retaining the bounded isolation/readiness handshake.
- Update Factory Reset/Rebuild operation plumbing so those actions surface nested provisioning/startup progress instead of sitting on one generic rebuild/reset spinner.
- Expand regression coverage to 171 tests, including legacy-instance migration, apt-free adoption, one-time installer semantics, and a two-boot regression proving the first upgraded start removes the old Lima provision block and the next normal start remains apt-free.

## v0.2.19
- Fix the live-chat NiceGUI use-after-delete race reported during long agent runs. Reasoning/status/answer callbacks are now bound to the exact chat-render generation and original message container which started the run, and proactively reject replaced tabs, deleted elements, disconnected renders and browser reloads before any UI mutation occurs.
- Keep agent execution and transcript accumulation independent from transient UI lifetime. Answer/reasoning chunks continue accumulating for persistence even after their original browser view is gone; attachment-strategy labels, tool cards, model phase labels, cancellation rendering and error rendering all use the same liveness boundary instead of relying on NiceGUI to throw after a stale write.
- Reconcile the active chat from persisted database state when an agent finishes, so switching away and back during a long run still reveals the completed answer without requiring another manual refresh. A deleted/disconnected old page skips reconciliation entirely.
- Add `live_agent_ui_detached` diagnostics with a bounded one-time reason (`render_replaced`, `tab_inactive`, `message_area_replaced`, or `element_deleted`) to make future UI-lifetime failures diagnosable without log spam.
- Expand regression coverage for render-generation invalidation, stale answer/reasoning accumulation, user attachment labels, tool cards, completion reconciliation, and deleted-element guards.

## v0.2.18
- Remove the legacy 20-step default cutoff and the hidden runner clamp that prevented any agent run from exceeding 60 model steps. Harnessy agents are now unlimited by default so long forensic, coding, build and research workflows can continue until the model finishes, the user stops the run, or a real terminal failure occurs.
- Add an explicit **Limit agent run by steps** switch under Settings → Agent / Tools. The finite maximum is only enforced when that switch is enabled; the editable guardrail supports large values instead of silently clamping at 60.
- Migrate existing v5 settings safely: an untouched legacy `max_steps: 20` is recognized as the old factory default and becomes unlimited automatically, while non-default finite values are preserved as intentional limits.
- Show unlimited runs as `Step N · Unlimited` in live status and emit `max_steps: null` in step diagnostics, while preserving the existing persisted `max_steps` terminal reason for explicitly limited runs.
- Add regression coverage proving an unlimited run can pass the former 60-step ceiling and still finish normally, while explicitly limited runs continue to stop at the configured boundary.

## v0.2.17
- Fix the remaining NiceGUI background-task violation in the model status bar. The async model ping no longer calls `context_label.tooltip(...)`, which creates a new `q-tooltip` and requires an active UI slot. The tooltip is now created synchronously with the status bar and the background ping only updates that existing tooltip's text.
- Include the pre-created context tooltip in the same render-generation and deleted-element liveness guard as the model dot and labels, so browser/tab teardown remains safe while a ping is in flight.

## v0.2.16
- Fix a NiceGUI use-after-delete race in the chat status bar. A delayed model-health ping can no longer update a model dot/label that was destroyed by a tab/status-bar redraw or browser reload. Each redraw cancels the superseded ping, assigns a render generation, and the async completion verifies both that generation and element liveness before touching UI.
- Keep unexpected model-status errors visible instead of swallowing every exception; stale/deleted UI races are ignored deliberately while unrelated failures still propagate to normal diagnostics/error handling.

## v0.2.15
- Make long VM starts observable instead of presenting a generic spinner. Harnessy streams Lima controller output during create/start, recognizes image/cache/disk/VZ/SSH/guest-requirement milestones, and surfaces real Lima percentages when the controller emits them. Carriage-return progress updates are handled live instead of waiting for a newline.
- Add truthful Environment operation telemetry: elapsed time, current-stage elapsed time, workflow position, measured Lima percentage when available, per-stage hard timeout, total operation timeout, and an ETA based on the recent median of successful runs. Until there is enough local history, the UI explicitly says it is learning an ETA rather than fabricating one.
- Expand Snapshot progress into explicit preparation, VM pause, checkpoint clone, metadata finalization, VM restart and isolation-verification phases. VZ clone copy percentages are shown when Lima exposes them, while elapsed/stage/deadline telemetry remains visible when it does not, so a slow snapshot is distinguishable from a hung one.
- Add a one-click **Download Diagnostics** icon directly beside the File Explorer shortcut in the Harnessy header. It refreshes the diagnostics bundle and immediately downloads the generated ZIP.
- Preserve the v0.2.14 VM readiness/controller architecture and proven `limactl start` command shape; this pass adds observability without reverting to direct guard execution, host fallback, or unbounded lifecycle waits.

## v0.2.14
- Replace the VM readiness guard's direct `limactl shell ... harnessy-network-guard` execution with a detached systemd oneshot job whose output stays in journald. Harnessy now queues the service with `--no-block`, observes it through separate short bounded `systemctl show`/stage-marker checks, verifies the ready marker and boot ID independently, and captures service state/journal/process evidence on failure. This removes the controller-EOF dependency that could leave a logically `verified` guard stuck until the outer Lima timeout.
- Make readiness synchronization process-wide per workspace. Independent provider instances share one start/readiness lock and one verified-boot cache, so simultaneous terminals/tools converge on a single isolation handshake and subsequent terminals reuse the verified boot instead of reinstalling/reapplying the guard.
- Bound all VM lifecycle/controller operations, including create/start/stop/delete/edit/snapshot/restore/reset/rebuild, and make timeout cleanup itself bounded (terminate → kill → stop waiting). Add command IDs plus command-start/finish/timeout/cancel diagnostics.
- Replace reload-sensitive Environment jobs with persisted operation IDs, stages, status, timestamps and total deadlines. Interrupted jobs are marked `interrupted` on restart and reconciled against the actual VM state without automatically resuming destructive work; non-Ready provider results cannot be reported as success.
- Centralize Environment inspection behind a process-owned, deduplicating status cache. Multiple tabs/clients share one provider inspection, recent failures are throttled, `limactl --version` is cached globally and concurrent-safe, and one inspection reuses its status result for snapshot listing. Lifecycle operations suppress background controller polling while active.
- Stop Environment background refresh from rebuilding the workspace sidebar. Busy indicators update in place, so workspace menus/dropdowns are not destroyed by status polling. Workspace terminal startup now observes the same backend-owned Environment operation and survives browser-page destruction.
- Constrain Environment Details/Snapshots content to a left-aligned 1080px maximum instead of stretching cards/labels to the far right. Keep snapshot naming/restore in dialogs and destructive actions in the Danger Zone.
- Make the Create / Select Workspace navigation surface non-selectable UI text and clear native selection on pointer interaction, while leaving the path and workspace-name inputs normally selectable/editable.
- Expand regression coverage to 151 tests, including detached guard completion, cross-provider start deduplication, shared status polling, one-time Lima version lookup, operation timeout/interruption recovery, controller cleanup bounds, non-destructive UI refresh, constrained Environment layout and workspace-picker selection behavior.

## v0.2.13
- Correct the first real-machine VM readiness failures found after the VM-first pass: replace the potentially blocking guard startup path with a deterministic no-DNS guest guard, install/repair it in-place for existing workspaces, run the authoritative post-boot guard directly under an 18-second guest timeout, expose install/apply/verify phases, and keep a Lima-powered-on VM distinct from a Harnessy **Ready** environment.
- Make Environment lifecycle jobs backend-owned and reload-safe. Start/Stop/Snapshot/Restore/Factory Reset/Rebuild persist their live phase/result, disable conflicting controls immediately, show an active loading state, and no longer report failures through a deleted NiceGUI slot after the initiating page disappears.
- Redesign the Environment surface into **Details** and **Snapshots** subtabs. Details contains the Environment/Resources/Files Bridge cards, normal controls, and a separated Danger Zone; Snapshots owns Take Snapshot, optional naming, snapshot listing, and Restore dialogs. Remove the detached far-right “CPU-only sandbox” header text.
- Persist the browser work session across page reloads: open chat/tool/Environment/Terminal tabs, tab order, active tab, File Explorer location, terminal numbering, selected workspace, and Environment subtab are restored. Settings saves preserve this live UI-session state instead of overwriting it with an older dialog draft.
- Keep Workspace Terminal PTYs process-owned across browser reloads and continuously drain PTY output into bounded server-side scrollback even while no browser poller is attached, so chatty commands cannot block during a refresh; a reconstructed terminal tab replays the buffered screen and resumes the same PTY.
- Fix repeated File Explorer `..` navigation by using a stable delegated click-pair listener rather than a native `dblclick` handler bound to the row which is destroyed/recreated after every parent navigation.
- Stop classifying normal Ctrl+C/KeyboardInterrupt shutdown as a Harnessy crash, while preserving real abnormal shutdown diagnostics.
- Make macOS LAN startup fully automatic: discover the active LAN IPv4 directly from the default physical interface using `route` + `ipconfig`, with `en*`/bridge fallback and no hostname/mDNS resolver dependency. The printed LAN-auth URL is therefore directly usable from another LAN device without a separate manual IP lookup.

### VM-first workspace execution

- Redesign new workspaces around a persistent per-workspace ARM64 Linux VM. The model runtime remains host-side; workspace shell/process/Git/LSP execution and Workspace Terminals run through the VM provider and never silently fall back to the host shell.
- Add a provider abstraction and Lima 2.x backend using Apple Virtualization.framework (VZ) + virtiofs on Apple Silicon macOS and QEMU + 9p on Linux ARM64. macOS Snapshot/Restore uses Harnessy-managed stopped Lima clone checkpoints because Lima native snapshots are not the VZ path; Linux QEMU uses Lima native snapshots. VM state is stored below the workspace `.harnessy/environment/` tree with a portable `environment.json` source of truth and no transient VM IDs.
- Add Ubuntu 24.04 ARM64 **General Development** and preferred **Reverse Engineering** presets. Workspace VMs are forced CPU-only; GPU passthrough, Rosetta, Docker/containerd and host accelerator exposure are not enabled.
- Introduce the dedicated host `Files/` ↔ guest `/workspace` live bridge. `.harnessy/`, `.LLM/`, host home, other workspaces and Harnessy/model internals are not mounted. Unsupported future copy/snapshot file-bridge modes fail closed.
- Add Start, Stop, independent Workspace Terminals, Snapshot, Restore, Factory Reset and Rebuild controls. Reset/rebuild preserve `Files/`; unregistering a workspace stops its VM when possible, while destructive folder deletion removes all colocated VM/workspace state.
- Stop running registered workspace VMs during normal Harnessy shutdown so idle workspace environments release host RAM/CPU while their persistent disks and `Files/` remain intact.
- Add sparse VM-storage reporting and a persistent `🛡 VM · Ubuntu 24.04 RE · ARM64 · CPU only` reversing-preset sandbox indicator.
- Disable implicit host credentials/features in generated Lima configuration: no SSH agent/X11 forwarding, no host SSH pubkey loading, no host proxy propagation, no containerd, no automatic guest-service port forwarding and no host-home mount.
- Add a persistent guest egress guard. Public-network mode permits public Internet while rejecting host/LAN/private/link-local/CGNAT/reserved/multicast destinations over IPv4/IPv6 and explicit Lima host aliases; DNS is limited to configured resolver addresses. Network-disabled mode default-drops new guest-originated egress while preserving the controller channel. Harnessy synchronously reapplies/verifies the guard after VM boot and fails closed before model/terminal execution if setup fails. Lima 2.2 does not yet provide host-side user-network egress policy, so this live-mode guard is documented as defense-in-depth rather than a malware-grade boundary against hostile guest root.
- Harden portable environment parsing so hand-edited definitions cannot enable GPU/non-ARM guests or turn unknown Files bridge modes into a weaker live mount.
- Reconcile Lima’s host-specific absolute mount binding whenever a stopped workspace has been moved/copied, and after VZ clone restore, so a copied VM cannot accidentally mount the source workspace’s `Files/`; keep that binding under runtime `state/`, not portable `environment.json`.
- Confine Workspace File Explorer browser events and upload targets server-side to `Files/`, including symlink/path resolution; keep Home File Explorer/Home Terminal as explicit user-only host utilities.
- Keep structured Git commits VM-local while disabling hooks with guest `/dev/null`; no host `.harnessy` hook path is disclosed through guest command arguments.
- Restrict host-side browser automation and VM-workspace web research to public-network targets; block local/private/reserved/file URLs and guard browser request/WebSocket routes.
- Protect the entire host-side Harnessy HTTP/WebSocket controller with a fresh per-launch access token and HttpOnly/SameSite cookie; carry the bootstrap credential only in a browser URL fragment so it never appears in HTTP request/access-log URLs; keep it out of Harnessy diagnostics; and change the new-install server bind default to `127.0.0.1`. When the user intentionally binds to `0.0.0.0`, print a per-launch LAN bootstrap URL to the local terminal so remote LAN browsers can authenticate instead of being locked out. This prevents a networked workspace guest from using Harnessy’s user-only Home tools or file-serving endpoints even if it can route to the host service.

### Reliability and diagnostics

- Keep LAN-address discovery startup-safe with a bounded daemon-thread probe, while macOS now reads the active interface directly instead of using hostname/mDNS resolution. A failed interface probe never blocks NiceGUI startup.
- Replace generation auto-follow debounce behavior with an explicit follow/pause state machine: the first upward user scroll immediately wins over streaming—even while still inside the near-bottom threshold. Paused follow can resume only after confirmed downward user input reaches the bottom, or through **Jump to latest**; generic DOM/streaming scroll changes cannot re-enable it.
- Fix native Ollama cumulative tool-call streaming by treating complete calls as snapshots instead of appending them as OpenAI-style deltas. Repeated `read_file`/argument snapshots no longer become duplicated names or concatenated JSON, and multi-tool transitions remain separated by call index/id.
- Make every terminal agent-run reason visible and persisted, including max-step exhaustion, cancellation, backend/parser/tool protocol failures, runner failures and VM/environment failures. Add live `Step N / max` telemetry.
- Add automatic host diagnostics for plain `python3 run.py`, starting before dependency installation so launcher/setup failures are captured too: rotating `harnessy.log`, `backend.log`, `tools.log`, `runtime.log`, `system.log`, bounded `backend-stream-tail.log`, console capture, session/crash retention and `.logs/Harnessy-Diagnostics-Latest.zip`. Large conversations/images/binaries are represented with bounded metadata rather than duplicated payloads.
- Log raw and normalized tool-call stream semantics, tool argument parsing/execution metadata, provider/model/request lifecycle, model phases, effective context, runtime metrics and VM controller/lifecycle identity.
- Harden guest long-running process wrapping so stdin remains connected and cancellation terminates the guest process group rather than leaving invisible jobs behind.
- Preserve Create / Select Workspace double-click folder navigation and reuse an existing copied workspace's portable environment definition instead of overwriting it with picker defaults.
- Keep streamed File Explorer uploads with no Harnessy size/type/extension cap, live progress/cancellation, partial-file cleanup and filesystem error reporting.
- Retain NiceGUI stale-element streaming hardening, compact model/tool bubbles, status-bar hover cleanup and prior context/provenance/runtime reporting fixes from the Checkpoint 21 baseline.
- Expand regression coverage beyond 100 tests, including Ollama snapshot semantics, terminal stop reasons, generated Lima YAML/provision-shell validation, VM routing/lifecycle, `Files/` preservation, path traversal/symlink boundaries, browser/private-network blocking and diagnostic bundle behavior.

## v0.2.12

- Preserve multi-step agent runs as chronological **Thinking → Harnessy → Tool → Thinking → Harnessy** transcript segments instead of appending later model iterations into one old assistant bubble. Tool invocations now render as compact, separately tinted, expandable cards with a one-line tail, arguments/result details, duration, and persisted reload behavior.
- Compact Thinking cards to one header plus one live reasoning-tail line, removing the duplicated Thinking label. Add live model phases for Ollama (**Waiting → Prefill → Generating**) and retain accurate per-model-call average generation TPS plus total call duration after completion.
- Fix destructive-dialog keyboard handling so Enter confirms and Escape cancels at the dialog level, add a 700 ms global tooltip delay, remove duplicate composer generation status, and stop showing historical image-context counts in current-send status.
- Make large pasted-text delivery observable and truthful: **Direct**, **Not retrieved**, or **Retrieved · N chunks**. Persist retrieval calls, chunks searched/supplied, characters supplied, and estimated supplied tokens in attachment/Performance diagnostics.
- Add a scalable tool registry with categories, core/discoverable exposure, structured execution telemetry/history, and **Off / Ask / On** permission families. Off tools are hidden and blocked server-side; Ask uses an Allow once / Deny approval flow. Add tool discovery via `list_tool_categories`, `search_tools`, and `describe_tool`.
- Add non-blocking long-running process jobs with start/poll/stdin/stop/list operations, incremental stdout/stderr, workspace-scoped job IDs, process-tree termination, and cleanup on Harnessy exit.
- Add structured Git tools (`git_status`, `git_diff`, `git_log`, `git_branch`, `git_show`, `git_commit`, `git_restore`) with read/write permission separation, root-bound path handling, and protections against hooks, commit signing, external diff/textconv, and parent-repository escape.
- Add isolated Playwright browser automation sessions (`browser_open`, DOM inspection, click/type, screenshot, wait, back/reload/close). Browser permission defaults Ask; screenshots remain private under `.harnessy/artifacts` and appear in Artifacts / Downloads.
- Add public-web research tools (`web_search`, `web_open`, `web_find`, `web_download`) with source metadata, private readable-page caching, private downloads, redirect/size limits, and blocking of local/private/reserved network targets by default.
- Add code-intelligence tools (`find_symbol`, `find_references`, `go_to_definition`, `workspace_symbols`, `diagnostics`) that reuse installed language servers when possible and fall back to bounded source indexing/syntax checks without executing project code.
- Add structured Harnessy self-diagnostics (`get_last_request`, `get_generation_metrics`, `get_context_usage`, `get_tool_history`, `get_attachment_strategy`, `get_active_model`, `get_backend_status`) while excluding model API credentials.
- Add layered Skills: built-in `skills/`, machine `.settings/skills/`, and portable workspace `.LLM/skills/`, with workspace > machine > built-in precedence, `list_skills` / `read_skill`, a composer Skill selector (Auto / None / named), compact Auto catalogues, and the first eight built-in coding/research/release playbooks.
- Update release documentation for the Home-only Terminal, Skills/Tools architecture and permissions, make the launcher User-Agent read the release version from `VERSION`, and expand the regression suite through the final integration pass.

## v0.2.11

- Convert very large clipboard text pastes into private `.txt` chat attachments under `.harnessy/uploads/<chat>/` instead of flooding the composer or project working tree. Pastes below ~32k characters remain inline.
- Use a hybrid large-text path: pasted text up to ~128k characters is supplied directly to the model; larger pasted text is retained as a chat attachment and exposed through `search_attachment` chunk retrieval plus ranged `read_attachment` reads.
- Fix the sent-attachment preview regression: pending composer attachments now clear as soon as the built request enters any `Waiting for model…` state, including Ollama image-status variants, while the permanent sent-message attachment remains.
- Make Ollama image status distinguish current-turn images from historical image context, e.g. `1 new image · 13 in context`, instead of presenting the cumulative request count as if all images were newly attached.
- Stop streaming auto-scroll from fighting the user: Harnessy follows the bottom only while the user is already near the bottom; manually scrolling upward suspends auto-follow until the user returns near the bottom.
- Dismiss active tooltips immediately on pointer interaction so tooltips cannot remain floating over menus/dialogs after their triggering control is clicked.
- Remove workspace-specific Terminal from the workspace `…` menu; the machine-level Home Terminal remains the single Terminal entry point.
- Fix live theme switching by retaining the page dark-mode controller and applying the saved theme directly to the active Quasar/browser client, so Light ↔ Dark changes repaint immediately without reload.
- Improve dark-theme dialog separation with a distinct elevated dialog surface, subtle border, and stronger backdrop contrast.
- Fix the partial-generation Stop path so stopping after answer text has started appends a clean `Generation stopped` marker instead of hitting the stale placeholder expression.
- Expand regression coverage to 45 tests, including private large-paste storage, large-text retrieval, stream-follow suspension, live theme application, tooltip dismissal, pending-attachment cleanup, and workspace-terminal removal.

## v0.2.10

- Truncate long workspace/chat labels and tab titles to a single line with ellipsis so unusually long folder names cannot expand sidebar rows or overlap tab chrome; preserve full names in tooltips.
- Add machine-level File Explorer and Terminal buttons beside Settings. These tools start at the current user's home directory, use a Home icon in their tabs, remain outside workspace ownership, and do not change the selected workspace.
- Replace the per-workspace action strip and row-level remove icon with a hover-only `…` menu containing Workspace Memory, File Explorer, ZIP / Downloads, Terminal, and Remove Workspace. Missing workspace folders still expose the menu so registrations can be removed.
- Add two archive extraction actions to File Explorer context menus: **Extract Here** (no extra Harnessy-created top-level folder) and **Extract to <archive name>**.
- Give the Thinking card a distinct muted violet surface in both light and dark themes.
- Reduce Markdown H1/H2/H3 sizing so model-generated headings remain proportional to chat text.
- Harden Ollama vision delivery with a Harnessy-private raw-image channel that maps directly to native `messages[].images`, bypassing the previous data-URL reparse step for native Ollama.
- When an image-bearing request targets an Ollama endpoint, prefer native `/api/chat` even if an old profile is left in OpenAI-compatible mode; text-only requests continue to honor the selected compatibility mode.
- Add a final-payload safety gate: if the current user message loses any expected images before the HTTP request is sent, abort and leave attachments pending instead of silently sending a text-only request.
- Expand vision telemetry with per-message image counts, per-image byte sizes, short SHA-256 fingerprints, and the exact vision transport used, without logging base64 image data.
- Expand regression coverage to 42 tests, including native raw-image transport, Ollama vision routing, global Home tools, long-name truncation, hover workspace actions, archive extraction choices, Thinking tint, and final-payload vision guards.

## v0.2.9

- Replace sidebar up/down ordering buttons with true drag-handle reordering for Workspaces and Chats. Rows shift live while dragging, the final order is persisted, and activity/selection/renaming never floats items automatically.
- Move **Remove Workspace** onto each workspace row so it remains reachable even when the registered folder is missing; missing paths are visibly marked and can still be unregistered non-destructively.
- Change the Create / Select Workspace browser to standard file-browser interaction: single-click selects, double-click opens, including the `..` parent row; retain right-click folder actions for create/rename.
- Make File Explorer permanent-delete confirmations keyboard-friendly by autofocusing the destructive action so Enter confirms the dialog.
- Keep the Thinking expansion/header at the full conversation width regardless of the live tail length.
- Clear the pending composer attachment preview as soon as the request payload has been built and the attachment is consumed, while preserving the attachment deck beside the sent user message.
- Fix the vision-agent conflict that caused models to report only filename/type/size: image pixels are supplied directly as multimodal input, image metadata is no longer injected alongside the pixel payload, the system prompt tells vision models to inspect pixels directly, and `read_attachment` refuses to impersonate an image viewer.
- Stabilize Terminal geometry by pinning the terminal panel to the tab content area, keeping the toolbar/title outside the xterm viewport, removing JS viewport-height writes, and adding balanced terminal gutters.
- Add regression coverage for image-tool behavior, manual chat ordering, drag-reorder UI semantics, picker click/double-click semantics, fixed terminal geometry, and the vision-agent rules.

## v0.2.7

- Make post-send latency visibly active: immediately create the pending assistant turn above the composer, scroll it into view, and show real request stages such as **Building request…** and **Waiting for model…** until reasoning or answer output arrives.
- Keep Thinking collapsed by default while streaming, show a continuously updated short reasoning tail when collapsed, expose the full accumulated reasoning only when expanded, and label it with the selected level such as **Thinking (High)**. Thinking Off never creates a visible Thinking card.
- Add per-send diagnostics for selected Thinking value, actual backend/API parameter sent, backend/endpoint/model, first reasoning token, first final-answer token, reasoning received while Off, completion state, image count/bytes, text length, and tool count.
- Harden vision delivery so image bytes are embedded before pending attachments are consumed, native Ollama receives real base64 pixel data under `messages[].images`, sent user messages retain image associations, and request telemetry confirms image count/decoded byte size without logging base64.
- Show persisted message timestamps with full date/time tooltips and date separators, and group user questions, Thinking, and assistant answers into restrained turn surfaces that remain clear in light and dark themes.
- Redesign Settings into a left main-section navigator with right-pane subsection tabs, retain unsaved edits while navigating, provide one unified bottom-right **Save**, warn before discarding dirty settings, mark restart-required server settings, and apply dark/light mode immediately after Save.
- Upgrade File Explorer with desktop-style multi-selection: Shift range selection, Ctrl/Cmd toggles, marquee selection, Ctrl/Cmd+A/C/X/V, Delete/Backspace, Enter, F2, Escape, multi-item copy/cut/paste/delete/ZIP behavior, selection-aware context actions, and a `..` parent-directory row.
- Fix terminal sizing so xterm fits the actual remaining tab viewport and refits on shell/panel/browser resize, keeping the final prompt/cursor inside the visible window.
- Allow repeated Terminal clicks to create independent **Terminal 1 / Terminal 2 / Terminal 3…** tabs with separate PTYs, scrollback, resize/input routing, and per-tab teardown.
- Preserve workspace registration order when selecting/touching workspaces; the selected workspace stays in place, highlighted and bold, and only its row shows the workspace action toolbar.
- Add **Remove Workspace**. Default removal only unregisters Harnessy and leaves the entire workspace folder, `.harnessy/`, `.LLM/PROJECT_MEMORY.md`, project files, and history untouched. Optional folder deletion is visibly destructive, requires typing exactly `DELETE`, and refuses to delete filesystem root.
- Expand regression coverage from 30 tests in v0.2.6 to 36 tests, including native Ollama pixel payload verification, delayed attachment consumption, workspace-order stability, non-destructive workspace removal, and UI guards for the new Settings/File Explorer/Terminal behaviors.

## v0.2.6

- Route local Ollama profiles through the native `/api/chat` path automatically in Auto mode, while retaining OpenAI-compatible chat completions for other endpoints. This gives Harnessy first-class Ollama image and thinking handling without tying chats to one backend.
- Send image attachments to native Ollama as actual base64 image payloads and verify reported model capabilities before consuming a pending image when capability metadata is available.
- Stream model reasoning into a collapsible **Thinking** block inside each assistant message and persist it with chat history instead of displaying reasoning activity beside the composer status.
- Make Thinking Off explicit (`think: false` for native Ollama and `reasoning_effort: none` for compatible endpoints) and make the composer Thinking choices reflect the configured API mode instead of pretending unsupported levels exist.
- Add optional Auto / OpenAI-compatible / Ollama backend selection and a model-capability detection action in Model settings.
- Persist chat scroll position per workspace/chat using a message anchor + offset with raw-scroll fallback; browser local storage provides immediate reload restoration and the same state is mirrored into the workspace `.harnessy` database for portability.
- Center pending image thumbnails and attachment controls.
- Change File Explorer interaction to desktop semantics: single-click selects, double-click opens, and right-click keeps the context actions.
- Add consistent content gutters to File Explorer and Terminal toolbars so controls no longer sit against the viewport edge.
- Replace the terminal PTY launch path with a controlling-terminal bootstrap, restoring normal Ctrl-key/job-control behavior such as Ctrl+C interrupting a foreground process.
- Increase the per-chat status bar height slightly and use native Ollama timing counters for TPS/prefill calculations when available.
- Add workspace migration coverage proving a copied workspace keeps its ID, chats, messages, project memory, and attachment history through its own `.harnessy` / `.LLM` state.

## v0.2.5

- Fix chat autoscroll so the view stays anchored to the newest response instead of jumping upward after generation completes.
- Remove the stray sidebar version/footer placement; version information now lives in Settings.
- Restyle assistant Markdown/body typography, headings, lists, and code for a cleaner chat-reading layout.
- Replace the sticky composer drag tooltip with a true drag-state overlay that appears only while files are being dragged over the composer and clears on drop/leave.
- Add pasted/attached image thumbnails before send and preserve image previews in chat history after send.
- Send image attachments as OpenAI-compatible multimodal `image_url` content when the selected model profile has Vision / image input enabled; block the send and keep the attachment when the profile is not vision-capable.
- Expand chat drag/drop so files from the OS can be dropped directly onto the composer.
- Fix tab active-state styling so the actually selected chat/tool tab is unambiguous while chat tabs retain their distinct type styling.
- Upgrade File Explorer with right-click context menus, copy/cut/paste, rename/move, delete, download, ZIP/extract, create file/folder, whole-tab OS drag/drop upload, recursive folder drops, drag-onto-folder destinations, internal drag move/copy, and browser-supported drag-out download.
- Batch File Explorer drag/drop uploads so a large folder drop refreshes once instead of once per file.
- Replace the textarea-like Terminal with a real Unix PTY + xterm terminal emulator: interactive shell input, ANSI colour/cursor handling, scrollback, resize, Ctrl+C, and white/coloured text on black.
- Cache terminal browser assets under `.vendor/harnessy_static` during `python3 run.py` and serve them locally so normal terminal use does not depend on a CDN after setup.
- Add regression coverage for PTY execution, multimodal image request construction, whole-area File Explorer drag/drop hooks, image previews, and the existing async UI-context protections.

## v0.2.4

- Fixed chat streaming on NiceGUI 3.x: Send/Enter no longer detach the chat event handler into a second background task, so streaming updates retain the correct client/slot context.
- Fixed the `AwaitableResponse must be awaited immediately after creation or not at all` startup/runtime warning by sending the browser upload-target JavaScript directly through the owning client.
- Streaming and terminal auto-scroll JavaScript now target the owning UI element's client explicitly instead of relying on global slot lookup.
- Added regression guards for the NiceGUI async-context failure patterns reported during live testing.

## v0.2.3

- Stop silently forcing `temperature=0.2`. Sampling now defaults to **Model default**, which means Harnessy omits the parameter entirely and lets the selected model/server decide.
- Add optional blank-by-default overrides for Temperature, Top P, Top K, Min P, Presence Penalty, Frequency Penalty, and Repeat Penalty.
- Migrate the old implicit `0.2` temperature to model-default automatically while preserving non-`0.2` legacy temperatures as intentional overrides.
- Extend **Fetch Models** with Ollama's native `/api/tags` fallback in addition to OpenAI-compatible model-list endpoints.

## v0.2.2

- Remove all references to the previous comparison UI/product name from code, UI text, tests, and documentation; compatibility controls now use generic OpenAI-compatible terminology.
- Rename the disposable local dependency directory from `vendor/` to `.vendor/` to keep the Harnessy root cleaner.

## v0.2.1

- Fixed NiceGUI dictionary-backed selects using reversed label/value mappings, which caused `ValueError: Invalid value: local-openai` when opening Models settings.
- Fixed the same mapping bug in the per-chat model picker and ZIP/Downloads chat selector.
- Added automatic fallback when `.settings/` references a model profile ID that no longer exists.
- Added a shared select-option helper and regression coverage so profile IDs remain the actual NiceGUI select values.

## v0.2.0

Major workspace/UI architecture pass based on the first macOS browser test.

### Persistence and workspace memory
- Move all machine-level Harnessy configuration/registry state into root `.settings/`.
- Add best-effort one-time import of existing `~/.harnessy` settings/workspace registry when `.settings/` is initially empty.
- Replace the previous structured workspace-memory/checkpoint UI with one transparent `.LLM/PROJECT_MEMORY.md` file per workspace.
- Migrate older structured memory/checkpoint entries into `PROJECT_MEMORY.md` where possible.
- Keep operational workspace state (chats/uploads/jobs/artifacts/metrics) in `<workspace>/.harnessy/`.

### Sidebar and work tabs
- Move **New chat** underneath CHATS and only show it after a workspace is selected.
- Replace the tiny workspace-add icon with a visible **Create / Select…** control.
- Add a root-capable directory picker for workspace registration.
- Show Workspace Memory, File Explorer, ZIP / Downloads, and Terminal icons beneath the selected workspace.
- Convert the right work area to tabs.
- Reopen/focus existing tabs instead of duplicating them.
- Label chat tabs with workspace + chat name and style chat tabs differently from utility tabs.

### Composer
- Move model selection into the message composer; chats/workspaces are no longer labelled as belonging to one model.
- Support changing model profiles in the middle of a chat.
- Add optional per-send Thinking level when the profile enables it.
- Add Chat Templates via the four-square button.
- Add normal file selection, drag/drop attachments, and clipboard image paste.
- Show/remove pending attachments before sending.
- Add configurable Enter-to-send behavior; Shift+Enter remains newline, and Cmd/Ctrl+Enter can send when Enter-to-send is disabled.

### Models and settings
- Split Settings into General, Models, Chat, Agent / Tools, and Server / Network.
- Add multiple model profiles.
- Add **Fetch Models** discovery against OpenAI-compatible `/models` endpoints (with `/v1/models` fallback).
- Add context/output limits and advanced OpenAI-compatible-style compatibility controls for streaming usage, vision, thinking/reasoning, developer role, strict tool schemas, max-token field, thinking-format note, and optional pricing.

### Workspace tools
- Add a Workspace Memory editor tab for `.LLM/PROJECT_MEMORY.md`.
- Add a File Explorer tab that starts in the workspace but can navigate from `/`; includes upload/drop, download, create, view/edit, rename, delete, ZIP, and safe extraction.
- Add a persistent Unix Terminal tab starting in the workspace directory.
- Add a ZIP / Downloads tab for packaging active chat working copies and retrieving artifacts.

### Chat status / metrics
- Add a per-chat bottom status bar with web/model connectivity, context use, cost/local indicator, cache information, messages, generation TPS, prefill speed, and average TPS when available.
- Add a detailed performance/context dialog with token counts, time-to-first-token, duration, last/average generation and prefill speed, generations, messages, endpoint/model, and cost.
- Record generation metrics per chat, using backend usage when provided and conservative estimates as fallback.

### Launcher
- Keep `run.py` as the only user-facing launcher.
- Cache the local vendored dependency installation using a requirements + Python-version hash so dependencies are not reinstalled on every start.

## v0.1.7

- Change the default Harnessy server bind from `127.0.0.1:7860` to `0.0.0.0:6767`.
- Automatically migrate the untouched legacy bind default to the new LAN-friendly default.
- Add configurable Bind Host and Port fields to Settings; changes apply after restart.
- Show explicit local/LAN startup URLs in the terminal.
- Make `run.py` the only user-facing launcher.
- Rename the internal direct application entry point to `harnessy_app.py`.
- Keep the `src/harnessy/` package layout to avoid Cloud Commander folder-name collisions.

## v0.1.6

- Move the internal Python package to `src/harnessy/` to avoid outer-folder/package-name collisions during Cloud Commander extraction.
- Add compatibility for legacy and flattened layouts.

## v0.1.5

- Replace the permission-sensitive shell launcher with a Python launcher and local dependency installation.
