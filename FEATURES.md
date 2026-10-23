# HarnessyXO v0.7.15 Features

## Context budgeting and retention

- **Context trimmed** cards keep their title, timestamp and summary visible. Expand **View context details** to inspect token counts, the counting method and context bookkeeping. Details start collapsed and retain their open state when the transcript redraws.
- Open **Performance / Context** to see how the last recorded request divided its total context between output, safety space, instructions/tools, controller notes and conversation. Token counts identify their source; estimates are marked with `~` and kept separate from completed backend usage.
- A context setting is a total-window ceiling. Output and safety reservations still apply. Initial requests use a conservative UTF-8 estimate until trustworthy measurements are available. An unchanged measured prefix can use its backend count plus conservatively estimated additions; rebuilt prompts need compatible observations before receiving a calibrated estimate.
- Supported llama.cpp servers can count the actual chat payload through their request token-count endpoint. Count requests use the same configured service and credentials, have bounded time and size limits, and fall back when unavailable. Other backends can learn from completed prompt usage; no tokenizer or model download is required. Changed request identities, tool schemas and unsupported media reset the learned view.
- Older saved work can leave the active prompt while remaining retrievable with chat-history tools. Keep at most one bounded controller note, including when migrating accumulated legacy markers. Actual trimming appears as a compact **Context trimmed** timeline event with its counts. The event stays out of model input; routine retention housekeeping does not become a fabricated assistant reply or an instruction to announce an archive event.

## Printable chat PDFs

- Open **Printable PDF** from a Project / Chat's menu, or use the **Printable PDF** button in the existing export dialog. Export the entire saved chat, selected prompts with their replies, or an inclusive saved-message range. Search message numbers or previews to select each end; activity rows count as saved messages too.
- Set each content section to **Full**, **One line** or **Nothing**: prompts, replies, Thinking, tool calls, tool results, prompt processing, events/completion checks and attachment references. Select timestamps, model/backend, token counts, speeds, elapsed time, cache statistics, titles and IDs independently. Compact entries retain their timeline position and wrap to fit the page. They contain deterministic labels/statistics, never AI summaries or hidden copies of the omitted body.
- See actual PDF pages in a paginated in-app preview, jump to any page, download those same bytes, or open the PDF for printing. Changing choices clears the old preview. A completed PDF is also saved in that chat's Downloads; closing the dialog does not cancel work, and Cancel export leaves the chat and model running.
- Snapshot saved history directly, independently of the current browser window. Preserve chronological Thinking/reply segments and selected prompt spans, include activity, and exclude unsaved streaming output. Selected prompts must still exist in the captured snapshot; stale selections never expand into a whole-chat export.
- Keep full tool results separate from call-argument metadata. Completion-check exchanges respect the reply and Thinking choices. Attachment Full lists saved reference metadata only; binary contents, arbitrary local paths and remote Markdown images are not fetched or embedded.
- Print long code, links and tables within page margins, splitting across pages when needed. Embed available supported host-font glyphs. Unsupported characters appear as visible Unicode codes with a warning instead of missing-glyph squares. Printable exports support up to 64 MiB of selected full text, 200,000 indexed messages/sections and 250,000 formatted blocks; exceeding a limit gives a clear error without a partial download.
- PDF setup uses the launcher's normal dependency installation. Preview pages and downloads require the signed-in account, current workspace registration and an unchanged completed PDF. PDF work has its own bounded queue and does not consume model generation slots. Existing Markdown and generated handover exports remain available.

## Named VM environments

- Create a workspace with its name and folder first. Open **Environments → Create VM Environment** to add named VMs whenever needed. A workspace can hold files and conversations before a VM exists; model commands never fall back to the host shell.
- Use the same VM interface for development and testing. Give each VM a name and optional purpose/model instructions. The model can discover enabled VMs and select one explicitly for each command; a running process and terminal remain attached to their original VM.
- Run multiple VMs at the same time. Each has its own OS disk, settings, installed packages, runtime jobs, status, snapshots and diagnostics. View combined CPU/RAM allocations and edit the stopped VM's resources independently.
- Open each VM in its own named tab under **VM Environments**. **+ Create VM** is always the last tab. Tab names wrap on narrow screens and the active VM is remembered. Keep one card per VM: **Manage** expands Details and Snapshots inline, and **Hide details** collapses them. One progress panel shows the current operation, stage, elapsed time and available progress/ETA, with one main control row. Overview counts distinguish starting, ready, stopped and incomplete VMs. **Retry Setup** resumes setup on an already running VM without resetting its disk.
- Change **Tool preset** later in **VM Settings**. Presets stay within the current OS. Compatible optional selections and installed tools are retained; review and install choices in **Manage Optional Tools**. New required packages are checked on the next Start. Finish active work before switching presets; VM storage, snapshots and project access are preserved.
- Keep VM editors open while background status/configuration refreshes update the VM list. Retain pending choices and typed values; unchanged permission fields preserve the latest saved grants when you apply a preset change.
- Choose shared project source with read/write access, read-only source, or a separate deployed copy where supported by the guest. Canonical project source, conversations and saved artifacts belong to the workspace. Dependencies, default build directories and caches belong to the VM. Shells expose `HARNESSY_BUILD_ROOT`, `HARNESSY_VENV_ROOT`, `XDG_CACHE_HOME` and `PYTHONPYCACHEPREFIX`; explicitly writing `./build` or `./.venv` in shared source still creates shared files. VM reset, rebuild and removal preserve canonical source.
- Use one shared file-access policy for model commands and project-files terminals: own files writable, parent/ancestor files read-only, direct Project Access sources read-only, and References read-only. Read-only VM mode also protects own files. VM selection stays exact per Project / Chat; children do not inherit VM permissions or their parent's extra Project Access grants. [VM_FILES.md](src/harnessy/environment/VM_FILES.md) records the complete contract for current and future providers.
- Apply VM access, Project Access and parent changes to running VMs. Refresh an affected subtree after reparenting; retain sources still needed by other allowed projects. Show verified runtime state separately from saved access. Busy views show **Unmount pending** until their tasks finish and project terminals close; unrelated projects can continue. Access changes never delete canonical files or independent guest data, and never start a stopped VM.
- Open a **Project files** terminal for an exact project, with the same file scope as model commands, or choose a **Guest console** for administration. Supported Lima Linux and opkg-based OpenWrt consoles automatically mount only workspace References read-only at `/workspace/Files/References`, including in separate-copy mode and with no projects. Project access and model enable settings do not restrict this human console input. Existing Lima VMs need one explicit Stop/Start to add the read-only export; unsupported Windows/APK consoles remain available with an explicit live-References limitation. Remember each terminal's VM, project and mode; a dead project terminal must be reopened against the current policy.
- OpenWrt Bash project terminals show your username, VM name and current directory. The path follows `cd`, and an existing custom Bash prompt can override the default.
- Use live bind views on supported Lima Linux guests and scoped SSHFS on compatible opkg-based OpenWrt guests. OpenWrt serves files on demand over existing SSH, avoiding a whole-project copy before opening the shell. The host enforces read-only inputs and rejects symlinks, multiply linked files and special files. Guest build/cache directories remain available for dependency trees requiring these entries. Windows and the APK-based OpenWrt image remain copy-only; independent copies never write back automatically, and explicit deployment/collection limits still apply.
- The stock OpenWrt 23.05.5 Malta big-endian option uses `mips_24kc`, musl and Linux 5.15.167. Its pinned package feed supplies Python 3.11.7. MIPS uses software CPU emulation on ARM64 and x86-64 hosts; it does not reproduce a particular router's peripherals.
- Expand optional tools during VM creation or manage them afterward. Show compatible package choices, required integration packages, installed/missing results and explanations for unavailable tools. A saved selection is not proof of a successful installation.
- Show managed-bundle removal only for presets that support it. Preview the installed bundles currently deselected and confirm the same list before uninstalling them. Deselecting ordinary package-manager tools leaves their installations and dependencies intact.
- **Enabled for model use** controls whether the model can select or start that VM. Human consoles remain available. Ordinary Shell, Processes, Git and file permissions continue to apply; a VM name or purpose never grants permission.
- **External Targets** connects existing SSH machines and devices. It has its own access gate and selected-action controls; locally created VMs use VM Environments instead.
- Set **Allowed projects / chats** on each VM or external target to **All projects / chats** or **Only selected projects / chats**. Selected mode shows individual checkboxes with project names and IDs; no selection blocks every model project. Parent/child and future projects are separate unless All is selected. Saved grants survive renames and ordinary settings changes.
- The model discovers only VMs/targets available to its own project. Recheck grants for each operation and after approval waits; guessing an ID does not bypass them. Revoking access blocks new commands and process input, while human consoles and cleanup controls remain available. Existing guest data and already running work are not erased by changing grants.
- Open VM terminals and supported guest graphical interfaces in named main-area tabs. Saved tabs retain their VM identity. Diagnostics retain opaque VM IDs and separate controller evidence for each VM.
- Open a guest console for OpenWrt, Windows and VMs using separate project copies without copying the workspace first. It starts in the guest home and does not automatically copy files back. Use project tools to deploy or collect files when needed. Supported Linux Guest consoles receive read-only References; model commands retain their project-specific views and transfer checks. Console References status is shown separately and included in content-free diagnostics. Mount permissions do not determine Linux root access: OpenWrt live/read-only project shells use `harnessy`, OpenWrt Guest consoles use root, and Lima users can use sudo.

## Workspace startup and VM resources

- **Remove Workspace** only removes the registration and stops safely identified VMs. It leaves the workspace folder, files, chat history and VM disks on disk. The whole-folder permanent deletion option has been removed.
- Choose a dedicated workspace subfolder. Home folders, system directories, mounted-volume roots, HarnessyXO application/settings folders and protected ancestors are rejected before workspace initialization. Existing unsafe registrations can be removed without opening or repairing their folders.
- **Use this folder** shows an animated loading indicator, the current opening stage and elapsed time while the workspace is checked. Folder and database checks run off the interface thread. Repeated clicks are blocked until opening finishes; a failed attempt keeps the dialog open for retry.
- Reuse an opened workspace when starting chats, processing queued work or reloading the page. Normal database writes do not repeat its full startup check. Give large databases additional bounded time for the first check; report busy databases separately from confirmed corruption.
- Sign in before saved workspace database checks finish. Show visible loading progress while bounded isolated workers check a coherent SQLite snapshot and initialize each workspace. A corrupt, unavailable or stalled workspace gets a persistent error instead of blocking the controller.
- Retain saved tabs for unavailable workspaces. Use **Retry workspace** after addressing the disk, **Extended check** to give a slow database more time, or **Repair workspace** to prepare a separate recovery copy. Loading an error panel does not start repair automatically.
- Track recovery stage, elapsed time and actual copy progress; cancel private-copy checks without replacing the originals. Refresh or sign in again to return to the same operation. Download a report with operational details and record counts, without conversations or SQL.
- Review a verified index repair and choose **Use repaired database**, then **Open workspace** to restore saved tabs. Require full integrity, relationship, schema and row-by-row checks before offering activation. Keep uncertain salvage separate for review; preserve original database and journal files, project files, VM disks and workspace identity.
- Pause work only in the workspace being recovered. If queued jobs remain after recovery, choose **Resume queued work** after reviewing them. Existing completion and backend holds remain in effect. If an activation was interrupted, choose **Restore original database** before checking or opening that workspace again.
- Open **Environments → select a VM → Details → Edit VM Resources** to change CPU, RAM and storage. Stop the VM and finish active workspace work first. CPU and RAM can increase or decrease; storage can only grow. Start the VM afterward to use the new values and expand its disk capacity. Existing files, installed tools and VM disks are retained.
- In the same Details panel, see measured guest disk used, total and free space with a usage bar, low-space/inode warnings and a timestamp. `/tmp` is separate and labelled memory-backed only when verified. Host disk-image allocation and image file length are separate from configured virtual capacity. Checks run in the background for running supported Linux guests, pause during VM operations and can be refreshed manually; stale readings remain explicitly last-known, and unavailable values never become zero. Windows guest reporting is unsupported; host allocation remains available. Diagnostics retain these content-free observations in `VM_STORAGE.json` without contacting a guest during export.
- See guest CPU usage, RAM used/available, cache and buffers, system load over 1/5/15 minutes, swap and uptime alongside storage. CPU usage is normalized across all guest vCPUs and needs two valid samples; I/O wait and stolen CPU time are separate. RAM use accounts for reusable memory, and fallback estimates are labelled. CPU and memory update about every five seconds through the same background observer while storage keeps its slower cadence. Stopped or unreachable guests retain clearly dated last-known readings. OpenWrt and Lima Linux are supported; Windows guest readings remain explicitly unsupported. Content-free resource observations are included in `VM_RESOURCES.json`.
- Check the current VM identity, stopped state and settings before applying an edit, then verify the controller's reported values before saving. An uncertain edit keeps the saved definition unchanged and explains how to retry without shrinking the disk.
- Keep VM resource settings and an explicit **Stop VM** control available on a workspace-open error, independently of the workspace database.
- Diagnostics distinguish SQLite corruption from locks, record bounded workspace worker failures and native signals, and label collector resource/version observations separately from recorded application state.

## Model progress across backends

- Keep total **Run** elapsed time visible throughout the current run, with a separate **Request** clock while waiting for or processing a model request. Keep the run clock on narrow screens and freeze it when the run finishes, stops or fails.
- See the completed model call’s decode speed on each Thinking and answer card, including compact Thinking rows. **Call … tok/s** covers the originating model call; **~** before a speed marks an estimate. Keep each card’s observed duration separate, and retain saved rates across reloads and tab changes.
- Use one current-request display for every backend. Show an animated wait with increasing elapsed time before output; show real prompt-processing counters, cache reuse and throughput when the backend exposes them. Explicitly report unavailable progress instead of estimating percentages or inventing live token rates.
- Ask native llama.cpp for streamed prompt progress. Separate newly evaluated work from cached tokens, including zero-work and fully cached prompts. Preserve native generation timing and final usage. Generic OpenAI-compatible servers receive only their supported common request options.
- Keep previous completed-call speed and time to first output on a separately labelled line while the next request waits. Reset current-request clocks and counters between calls and keep chat/profile state distinct.
- Update quiet status after each health probe. Backend reachability does not prove inference progress; repeated counters and stream heartbeats do not reset the work-progress deadline. Keep cancellation and existing request deadlines.
- Backend versions and proxies can omit progress even when requests succeed. In that case the shared display continues to show a truthful wait until output arrives.

## VM consoles and readiness

- Manage locally created guests in **VM Environments** and connected machines/devices in **External Targets**.
- Keep numeric CPU, memory and disk bounds valid while switching guest OS or architecture. Apply OS defaults under the new bounds and preserve in-range values for architecture-only changes.
- Spot a ready test VM by its bold green Ready badge and check icon beside the name, green card outline and subtle tint. Other states have distinct icons and colours; the status wraps on smaller screens and stays readable in light and dark themes. A stopped, paused or unavailable current state clears an earlier Ready result.
- Open guest Shell, LuCI Web UI and noVNC Desktop views as separate main-area tabs, preserving selected targets across browser reloads.
- Keep guest pages isolated from HarnessyXO's browser origin; scope display access to the signed-in session and selected target, and revoke it on close or VM changes.
- Verify OpenWrt readiness without requiring a hostname utility. Separate boot, shell and optional radio setup stages, with a bounded readiness deadline.
- Retain target lifecycle evidence separately from busy model logs and include bounded QEMU/Lima boot evidence in diagnostics.
- If QEMU’s launch handoff times out, verify this target’s live monitor and identity before continuing shell/bootstrap checks on the same disk and ports. Capture launcher output without waiting for a daemon to close inherited output handles.
- Show stage, time limit and code for start errors, including empty timeout exceptions. Offer **Retry Start** and distinguish a running guest with incomplete setup. Correlate later successful guest probes with earlier launch failures in diagnostics.

## OpenWrt radio emulation

- Request two guest mac80211_hwsim Wi-Fi radios, installing matching signed official packages and verifying both PHYs and usable virtual interfaces before claiming activation. Create missing hwsim interfaces without replacing existing wireless or LAN configuration.
- Select **Emulated Bluetooth controllers** to install matching official guest packages and start two software controllers automatically. A bundled static BlueZ helper connects through private H4 pseudo-terminals and OpenWrt’s HCI UART driver, without replacing the guest kernel or rebuilding the VM. The helper runs on ARM64, x86-64 and the available MIPS variants. Verify actual controller registration and owned transports before claiming activation. OpenWrt 25.12.5’s stock BlueZ 5.83 daemon has big-endian MIPS management serialization bugs (malformed controller-capability and blocked-key messages). The Linux 6.12 big-endian scan ioctl can also silently disable scanning despite a successful hciconfig piscan; use a byte-sized HCI Write Scan Enable command and inspect the result. Controller registration does not establish full daemon or profile compatibility; verify the intended operation and report any daemon isolation used for raw HCI tests.
- Tell the model which capabilities are requested, last observed or currently verified, and label virtual radios as emulated with no physical RF or USB chipset coverage.
- Unified OpenWrt VMs stream the bundled Bluetooth helper over SSH input. Supported opkg images fetch matching radio packages through the host installer even when guest internet is disabled. **Retry Setup** repeats incomplete setup on the existing VM. Diagnostics retain setup phase, helper size/hash, transport errors and reviewed package failures without the helper payload or arbitrary guest text.
- Show a live spinner, indeterminate progress and the current stage while a test VM starts or sets up radios; stop the animation when the operation finishes. Use **Set up / repair radios** on a running target to retry its saved selection. Probe live capabilities after an application restart. Show setup progress, package/network/kernel failure categories, and per-radio results in the UI and support diagnostics. Incomplete requested setup reports failure while leaving the VM shell available.

## Automatic Linux Lima setup

- On Linux ARM64 and x86-64 hosts, install a verified private Lima 2.2.1 distribution with matching additional guest agents when `python3 run.py` or VM Create/Start finds Lima missing. Keep an existing usable Lima on your PATH in preference to the managed copy.
- Verify official release checksums, stage the complete tool bundle before activating it, and reuse a verified cache offline. Restore the managed tool path inside the application process without changing shell profiles or system PATH settings.
- Keep ordinary host package installation and privilege checks for QEMU and other required tools. Run HarnessyXO with your normal account; official Lima refuses root operation.
- Homebrew setup checks actual install/upgrade rows and the required dependency list. Missing prerequisites can be added with VMs running; required library updates need stopped VMs. Startup shows the package/version plan and records it in diagnostics. Installed Lima/QEMU replacement, unrelated upgrades and removals remain explicit host maintenance tasks.
- Recognize Homebrew's download, manifest and cache progress without treating it as a package change. Require a complete, verified install plan before installing prerequisites.
- Starting `python3 run.py` can complete normal Linux KVM group setup. If needed, the host terminal asks for your sudo password to add your current account to the standard `kvm` group owning the device. The launcher then restarts with refreshed group access and verifies the device before continuing. An account already added to the group skips the administrator command.
- Keep automatic group refresh to one attempt and run the app under your normal account. Noninteractive launches and restricted or nonstandard host devices show the remaining setup requirement. Passwords and terminal authentication output are not collected by startup diagnostics.
- Before native Linux QEMU Create/Start, check the current process's effective access to the existing KVM device. A permission denial gives `KVM_ACCESS_DENIED` and host repair instructions instead of allowing QEMU to fail after launch. Group changes require a new shell or login before restarting HarnessyXO.
- Check KVM access before Factory Reset, rebuild and snapshot restore can stop or replace guest state. Blocked operations preserve the current disk; Stop/Delete remain available. Keep foreign-architecture software emulation, absent-KVM behavior and macOS VZ unchanged.

## Public GitHub startup updates

- See `HarnessyXO version: X.Y.Z` in the CLI after the update check. An update relaunch reports the new installed version; an unavailable check or skipped update reports the installed version being started.
- Check `effishen/HarnessyXO` before application imports when starting `python3 run.py` on macOS or Linux.
- Apply clean `main` updates through fast-forward Git history and restart the launcher before setup.
- Verify every application byte before adding Git metadata to a ZIP installation. Restore executable metadata lost during extraction only after content matches; accept an untouched current-main ZIP against its exact current commit. Keep genuine source edits untouched and report the app-relative mismatch and reason. The first public check needs Git and internet access, without a GitHub account.
- Download updates from the public repository over HTTPS without GitHub login. Existing SSH checkouts keep their saved remote; the updater reads the matching public HTTPS source.
- Include reviewed source-check and historical host REA storage evidence in `STARTUP.json` and the support summary, retaining bounded launcher receipts when the app starts.
- Preserve settings, dependencies, runtime caches, workspaces and local code edits. Keep the current app available when a check fails.
- Hold an installation lock for the lifetime of the app and detect incomplete source updates across restarts. Keep it through launcher exec handoffs, then prevent native VM children and forked workers from retaining the app's lock. A stopped server releases its own descriptor.
- Starting `python3 run.py` on macOS or Linux automatically stops this folder's existing launch-lock holders and continues startup. No restart flag or confirmation is needed. This also covers VM children left holding an inherited lock by older releases.
- Try normal termination first, then force-stop verified original holders that remain. Other installations and model servers are outside the cleanup target set. Force-stopping a VM can lose unsaved guest work. Keep the lock file intact.
- Automatic cleanup needs `lsof` and `ps`, and refuses to stop processes whose ownership, identity or lock-file identity cannot be verified. Windows keeps manual shutdown behavior. Other OS lock failures show their error code.
- Publish versioned GitHub Release notes and verified downloads from committed application files, with the same 11 Markdown resources and no QA payload.

## REA in the workspace VM

- Install Reverse Engineer Anything as the ordinary `rea` command inside a reverse-engineering workspace VM. The model discovers the installed version and commands using `command -v rea`, `rea --version` and `rea --help`, then uses the normal shell or long-running process tools.
- Use **Workspace Environment → Manage Optional Tools → Apply / Retry Selected** with REA selected to install or check the latest published stable npm release. Existing VMs can install it in place. Normal command execution reuses the installed version; it does not download a new version for each analysis.
- Stage and verify guest installation before switching versions. Keep a working guest installation if an update fails. Public outbound access is required for downloads; an offline selection stays pending.
- Keep the supported Node runtime and npm package inside the VM. `python3 run.py` no longer installs a host REA server, and REA has no separate permission family or host MCP settings panel. Shell and long-running process permissions apply.
- Native analysis engines must be available inside the same VM. The reverse preset already offers Ghidra; use REA's installed help and readiness checks for exact capabilities and missing engine requirements.
- Preserve existing host REA settings and cache files for rollback. They are inactive and are not copied into a guest or deleted.
- Retain the lean package: three living documents and eight functional skill files.

## Run queue recovery

- New chats use the same global run queue. Interrupted completion work and backend recovery can pause waiting prompts across chats and restarts. Click **Agents** at the bottom to inspect the owner and use **Resume queue** after active checks or retries settle.
- Removing a workspace retires its settled blocking completion holds and cancels its pending queued runs atomically. Startup also clears settled completion holds whose workspace registration was removed by an older version. Registered workspaces remain protected even when their folder is temporarily unavailable; backend-recovery holds keep their existing explicit recovery controls.

## Storage concurrency

Workspace and machine databases use WAL so background reads can coexist with message writes. Store connections close promptly. Attachment authorization avoids transcript bodies; checkpoint badges retain full signed recovery checks while reading only relevant boundaries. Recurring transcript/navigation reads are offloaded from the UI event loop.

## Actionable support diagnostics

- Include QUEUE_STATE.json with bounded technical queue and hold state, observed admission gates, slot capacity and Resume availability. Correlate blocking owners by IDs without exporting project names, model names, prompts, replies, attachment metadata or arbitrary reason text. Snapshot the existing live queue at startup, on state changes and before a diagnostics download.
- Highlight a recorded QEMU KVM permission denial and corroborating host device/process-access facts near the start of the support summary. Distinguish the launch cause from QMP cleanup errors; a process's active groups do not establish the account's saved group membership.
- Include scrubbed host-agent and QEMU control-plane errors in the default download, rather than only recognized signal codes. Keep unfamiliar technical wording while excluding credentials, private paths, command payloads and guest console content. Guest serial logs still contribute fixed boot/error signals without guest output.
- Preserve bounded failure receipts before Start, Factory Reset or rebuild replaces the current VM logs. Retain controller command and lifecycle correlation, requested VM configuration and resource snapshots with their capture time; identify stale or prior-attempt sources explicitly. Capture test-target QEMU launcher output separately from guest serial output.
- Include HOST_STATE.json with read-only host prerequisites, OS/CPU, memory/swap and cgroup limits, resource pressure, disk/inode space, application process counters, KVM access, firmware metadata, known tool versions and dependency versions when available. Mark unsupported platforms and unavailable probes explicitly. Export-time host state does not establish resource availability at an earlier failure.
- Preserve typed exception facts through bounded cause chains: errno and DNS codes, subprocess exit/signal, timeout, HTTP status, TLS verification code and JSON position. Keep source frames without locals, source lines or arbitrary exception bodies.
- Include a per-source export ledger with original/read/export sizes, projection, truncation, exclusions and collector failures. Retained logs have stated limits; missing evidence is not a successful health check. Collecting diagnostics does not start, reset or repair a VM.
- Put the current model request, its wait and the previous completed call near the start of SUMMARY.txt. Include MODEL_REQUESTS.json with bounded correlation, coverage and timing evidence; distinguish current waits from older VM incidents.
- Retain timestamped, locally correlated numeric prompt progress, usage and native timings without copying model text, tool arguments or token-ID arrays. Use explicit correlation for new requests and label legacy timestamp candidates and missing evidence. A local request ID does not establish provider-side inference activity.
- Include bounded Lima guest boot and host-agent evidence in the normal download. `VM_LOGS.json` reports available, missing and limited sources; raw tails use the existing content option.
- Record fixed boot/SSH milestones and distinguish native controller failure, HarnessyXO timeout and cancellation. Observe status after startup failure without retrying a blocked model command.
- Capture trusted lifecycle progress without making controller completion depend on inherited output pipes. Report controller process state, elapsed wait and output activity while a command is pending; keep VM readiness dependent on the normal guest, provisioning and isolation checks.
- Preserve the original controller or setup timeout and failed stage. Use the total-deadline message only when the overall environment deadline actually expires.
- Give Lima's readiness-event wait the same 20-minute allowance as HarnessyXO; retain guest-requirement limits and the existing isolation/readiness guard.
- Open `SUMMARY.txt` first for recent failures and their code/database/tool context; inspect `INCIDENTS.json` for structured evidence.
- Include previous-session incidents after restarting, with session scope and bounded coverage stated explicitly.
- Retain exception causes, module/function/line and numeric SQLite codes without source lines, locals or exception bodies.
- Record operation origin, elapsed wait, configured busy timeout/journal mode, connection/transaction identities, transaction age and actor, and candidate competing transactions or unfinished result cursors.
- Capture bounded code-stack samples during event-loop stalls with an independent observer.
- Record sign-in verification and workspace-restoration stages separately. Capture native Python fault signals and reviewed code frames when no existing crash handler is enabled; default exports exclude raw paths, locals and source contents.
- Distinguish successful tool execution from failure to save its result.
- Keep database evidence content-free in both modes and avoid opening application databases while collecting diagnostics.

## OpenWrt test-target releases

- Choose OpenWrt 23.05.2 or 25.12.5 in the existing Create VM operating-system selector.
- ARM64, x86-64 and release-specific MIPS Malta choices use the selected release’s pinned kernel and writable ext4 filesystem. OpenWrt 23.05.2 offers MIPS32 big-endian; 25.12.5 offers MIPS32 and MIPS64 in both endian variants. MIPS uses slower software CPU emulation, not vendor router board emulation.
- Existing targets retain their configured release and disk.

## Reasoning grounded in verified facts

- Built-in guidance assumes factual recall from training is outdated until verified.
- Search and read authoritative sources before substantive work, including facts that seem familiar.
- Reason from evidence; match documentation to installed or target versions and investigate conflicts with local observations.
- Existing Web Off / Ask / On permissions continue to apply.

## Resume from a saved model/tool group

- Save one coordinated checkpoint after all tools requested in a response finish, or after a completed assistant response. Mark only the group's final visible bubble **State saved**.
- Right-click a marked bubble and choose **Resume from here** to restore the corresponding conversation, owned project files/Git state, memories, task state and attachment links, then continue the existing task with `continue`.
- Keep the original user prompt once in retained history and avoid resubmitting its attachments. **Undo latest rewind** recovers the abandoned timeline and files.
- Reject missing or corrupt checkpoints. Interrupted, truncated and unfinished groups do not receive a resume point. Related managed background processes must finish or stop before capture or restoration.
- Reuse unchanged file data and exact content verification receipts. Newly encountered large files require an initial full content check; saving therefore has some disk and processing overhead.
- Resume points restore managed project/chat state. External device/service actions and live VM/process/browser state have their own recovery requirements.

## Gradual context recovery

- Start recovery from the estimated history in the current assembled request. Keep whole-input usage, fixed instructions and tools, retained-history target and configured ceiling distinct.
- Allow up to 24 small downward retries for recognized capacity failures before generated output. Stop remains available throughout recovery.
- Reassess capacity gradually using successful normal requests. Failed upward trials increase the cooldown; trials remain bounded and respect the selected ceiling.
- Retain compact tuning diagnostics across sessions, independently of the large runtime log. Show backend-measured input when supplied and label estimates explicitly.

## Prompt navigator

- Remember the marker window separately for each user, workspace and chat. The down arrow keeps it at the newest markers across rebuilds, switches, reloads and appended prompts; browsing earlier markers preserves that position independently of transcript follow.
- Keep queued Latest intent through the task between a refresh acknowledgement and the pending jump. Tab/page/periodic saves preserve it, and a newer upward gesture cancels the deferred jump.

- Keep follow-latest intent through chat-tab switches, background browser tabs, redraws and reloads. Save Latest immediately while history is loading; preserve paused reading when you scroll up.
- Hold the paragraph or line you are reading steady while older/newer history loads and content finishes laying out. Capture any continued scrolling before replacing the page; ignore temporary browser clamping, preserve deliberate gestures, and recenter around your current message if you reverse direction during loading.
- Use clickable grey rectangles for earlier/later hidden marker pages instead of a visible scrollbar. At an end the rectangle disappears. Wheel, touch and keyboard still scroll the marker list independently.
- Use the top arrow to jump directly to the beginning of the chat and marker list; the bottom arrow jumps to latest and follows while revealing the list end.
- Keep a 10 px grey rounded square for every user prompt, including bookmarked prompts. Long marker lists scroll independently of the transcript.
- Insert purple rounded squares for selected events and bookmarks between prompts. One event entry uses a 7 px square; more entries gradually increase the square to a maximum of 11 px. All squares have 24 px click targets.
- Open an animated pointed menu from a purple square. Show the related original prompt, event excerpts, colored icons, timestamps and icon-labelled category counts. The square itself contains no logo or number.
- Save navigator visibility, bookmarks and independently selected errors, context tuning, attention, stopped runs, recovery, pending approvals and Completion Check. All event categories default off. Historical failures remain navigable after recovery.
- Retain every prompt and exact selected event once, including independently bookmarked Thinking/reply segments. There are no New badges. Grey and purple fills remain consistent when selected, with a teal outline indicating selection.
- Use Browse all to search every prompt and selected event. The unchanged bottom down arrow jumps to the latest messages.
- Close the menu after a successful jump so the destination is readable; reopen to see its selected entry. Loading or failed jumps keep the menu available. Another group, outside prompt, Latest or Top closes the previous menu.
- Support keyboard navigation, Escape and reduced motion. Preserve open menus through same-chat refreshes and resizing while their existing members remain available.
- Show immediate loading feedback for off-window bubbles, retain the latest destination through concurrent history updates, and offer Retry navigation after a delayed acknowledgement. Surrounding history remains scrollable.
- Hiding categories affects only navigation. Saved prompts, bookmarks, transcript and actual approval requests remain intact. Both legacy layout preferences use the consistent grey/purple marker design.

## Tool approvals

- With a permission set to Ask, queued/retried and direct runs wait for Allow once, Deny or Stop run. The card shows the original prompt, actual held slot and exact tool arguments; the sidebar also says Needs approval.
- Reloading, switching projects, closing a tab or signing out does not silently decide the request. Reopen the chat or Run queue to act from a valid signed-in session.
- Allow once applies to one request; an identical later command needs its own approval. Stale controls cannot decide or stop a newer run. Saved permission changes apply during active runs and pending approvals. Off blocks execution even after an earlier Allow; explicit Deny and Stop remain final for that request.
- External Targets is an access gate: Off blocks target calls, Ask requires approval and On permits access. Each target independently selects **Allow Full Unrestricted Access** or **Allow Only Selected Actions**. Selected actions each have Off, Ask and On controls; global On never overrides action Off or Ask. Full access enables every target action within the remote account's privileges and still obeys the global gate.
- Set external-target permissions for status checks, file listing, commands, copies, command categories and paths. Selected command categories use best-effort text checks, not an OS sandbox. Save and restore selected choices when switching to full access. Existing targets keep their restrictions when upgraded or edited.
- Use **Enabled for the model** on an external target card to disable model access without deleting its connection or changing selected actions. Use **Enabled for model use** on a VM card to prevent model selection/startup separately from its running power state.
- Expand **Allowed actions and command limits** beside a target’s Model access to see the approval rules, global overrides, exact SSH blocked command names and protected paths. SSH command filtering remains separate from approval. Local VM command capabilities are reported by the selected VM integration. Refresh the breakdown after changing global permissions.
- Opening tabs and changing workspace or navigator preferences preserve permission changes saved from another page.
- Export reviewed permission decisions and separate approval/tool execution timings in `PERMISSIONS.json`; show missing historical measurements as unrecorded.
- Waiting tools show Waiting for approval and accrue no execution time. Other queued work waits for the retained slot. A server restart interrupts the run; pending approvals are never replayed automatically.


## Linked prompt actions

- Stop, retry, queue and replacement status identify the actual source prompt. References open and highlight that prompt, including outside the current history window.
- Retry sends `continue` in the saved conversation and preserves existing work. The original prompt and attachments remain in history. The saved retry remains a separate attempt, displayed compactly with its original reference.
- Inspect the actual attachments for each attempt using the same attachment cards and gallery as chat messages.
- Clean cancellation before restoration clears its progress notice. Cancellation after restoration retains the edited draft and attachments.

## Login session timeout

- Choose Never, 15 minutes, 30 minutes, 1 hour, 6 hours, 12 hours, 24 hours, 7 days or 30 days in Settings → General. Never is the default.
- Save applies a changed policy to currently valid sessions without restarting the app. Timed sessions start at sign-in or a policy change; ordinary activity does not extend them.
- Logout, account revocation and server restart still invalidate sessions.

## GPU-hang recovery

- Retry the failed model request once per run after a reported GPU hang, before any generated output. Preserve completed tools and show an inspectable recovery activity. Stop cancels the delay or retry.
- Hold other queued runs during recovery. A successful retry releases its own hold; ordinary generation recovery failures, Stop and restart retain their separate hold policy and **Run queue → Resume queue** recovery control. Exhausted GPU recovery during completion verification releases only that run’s finished recovery hold, leaving the project unconfirmed while queued work proceeds. Pending jobs can still be removed.
- Keep ordinary backend errors, memory tuning, and long prompt-processing waits distinct. No automatic backend restart or replay of partial responses.

## Auto context after Stop

- Stop closes the current run to further steering immediately. Send during its cleanup saves the complete prompt and attachments as a fresh queued run.
- Fresh runs begin at the configured context ceiling (subject to observed backend limits); automatic reductions from the stopped run do not carry forward. The new run can tune down again if the backend rejects its request.
- The handoff survives tab switches and reloads. Normal in-run follow-ups, tool steps and automatic continuation preserve current tuning.

## Final-reply completion checks

- **Completion Check** is on by default in **Settings → Agent / Tools → Agent Settings**. Save the toggle to change it for new runs. When off, a successful run finishes and lets the queue advance without an extra verification request. When on, every nonempty, tool-free apparent final reply is checked with the active chat’s model, regardless of length. HarnessyXO parses a strict COMPLETE, CONTINUE, or NEEDS_INPUT decision mechanically.
- CONTINUE must name an existing unmet user requirement and a concrete authorized next action. The neutral check instructs the model not to continue for optional polish or invented scope; the working model is told to conclude if the request is already satisfied. These are model judgments, not proof of completion or incompletion.
- Show a checking/finished activity bubble with an expandable record of the original reply, check prompt, model response, and optional thinking. Display the actual continuation count and action; NEEDS_INPUT displays the question.
- Allow up to three decision attempts for each apparent final reply, with separate lifetime check counts. Two automatic continuations without new successful tool work remain bounded; distinct successful tool work renews that allowance. Exhausted verification leaves the project **Completion unconfirmed** and lets other eligible queued projects proceed. Continue and Retry preserve their established saved-work behavior and use normal queue order.
- Keep the full candidate reply in the check request, subject to the backend's real input budget. A check that cannot fit or finish cannot confirm completion. Explicit Stop, backend failure, output-limit recovery and tool-approval waits retain their separate handling. Checks have their own output cap and deadline.

## Recent context when resuming

- When an older turn is too large to fit as a whole, select its original user objective and a bounded contiguous tail of recent completed work, alongside newer turns and the current prompt.
- Keep assistant tool calls and matching results together, including multiple calls. Never bridge an incomplete or oversized recent block by silently substituting unrelated older steps.
- Final context budgeting remains authoritative and can compact selected history further. Saved conversation and project files remain available; this change does not fabricate a semantic summary or guarantee that every prior detail fits.
- Fresh-run Auto context resets still use the configured ceiling. Detailed selection reasons and counts are available in privacy-safe diagnostics.

## Sidebar run status

- Project title, ID/access information, and current or queued status share one selectable project button. Status stays inside the selection highlight; idle rows remain compact and long names retain the available title width.
- Running projects show their actual agent slot, including prompt processing (**PP**), direct chats and queued/remote runs. Temporary subagent slots appear in the tooltip; concurrent slots have a compact additional-slot count.
- Pending requests show **Q#number · Auto** or **Q#number · Slot number**. The pending slot is a preference, not an allocated slot. A running chat can also show its next queued request and additional-request count.
- Timeline replacements use a history icon while waiting/restoring and when their edited prompt enters the queue. Before restoration, show the blocking project’s actual slot when one is identified; the replacement itself has no allocated slot or agent-queue number yet.
- Hover for status details. Click the project name, ID or status to open its chat; use **Run queue** to view or cancel pending requests. The existing half-second timer updates rows in place, including queue renumbering, menu availability and completion/cancellation cleanup. Direct live requests without a saved queue entry show a separately labelled **Wait #number**.

## Automatic paste attachments

- Convert one pasted text block of 16,000 characters or more into a private `.txt` attachment, keeping the complete text. Smaller pastes remain editable in the composer. This is a per-paste browser string-length threshold, independent of the accumulated composer length and model tokens.
- Moderately sized current pasted attachments can still be supplied directly to the model, subject to context budgeting. Historical or very large pasted attachments remain available for targeted retrieval. Conversion alone does not guarantee smaller model requests.

## Retry queued runs

- Retry notices identify the previous run and offer continuation with its saved conversation. Timeline replacement hides these notices while working, then permanently retires notices for the replaced prompts when restoration commits. Cancelling before restoration keeps the original retry available.

- Select **Try again** on a stopped-run notice or in the run queue's **Recent attempts** section. Retry a stopped, cancelled, failed or interrupted attempt without entering its request again, even after reloading the page or restarting HarnessyXO.
- Queue `continue` with the saved model profile and thinking setting after a started run stops. Keep original attachments in history. Requests cancelled before starting still queue their unsent request with private attachment copies. Existing files/history and the current composer draft stay intact. A retry uses the project's current state; it does not undo tools or rewind the timeline.
- Preserve the requested slot when it still exists; otherwise use Auto and explain the change. Missing attachments or a removed model profile produce an explanation instead of an incomplete retry.
- Repeated or concurrent clicks create one retry per attempt. Earlier attempts remain recorded. Dismissing the chat notice leaves retry available in recent queue history; a subsequently stopped retry can itself be retried.

## Queue notices follow saved history

- Retire a queued run's startup card when its exact prompt is saved in the transcript. Long runs, history paging, tab changes and browser reloads cannot make a saved prompt appear unsaved again.
- Observe checkpoint completion independently of queue status and browser transcript refreshes. Retiring a notice leaves the reader's scroll position and the active run unchanged.
- Offer **Stop run** while a queued run is starting. The control targets that particular run; a delayed click cannot stop a later request. Pending prompts still have Remove, and unsuccessful attempts have a compact, dismissible retry notice.

## Timeline replacement in the background

- Keep replacement progress and its spinner inside the chat column. Show the current blocking project and its occupied agent slot during a project-file wait; identify a blocking history save separately from model generation.

- Confirm **Edit & replace timeline** to close the dialog immediately. A progress card above the composer names any project holding the required write lock and offers Cancel during the wait or restoration. Other projects remain usable.
- The operation survives tab changes and browser-page reloads within the running HarnessyXO process. After restoration, the persistent queue takes over for agent-slot admission.
- Keep using other projects while waiting. The queued prompt and attachments remain visible after tab switching or reload, with the selected model and thinking setting retained for execution.
- Remove the queued prompt before it starts to cancel it. If queue storage fails after restoration, the edited text remains as a draft and attachments return to pending; removing a queued prompt does not undo the completed timeline restoration.
- Cancelling before restoration leaves the timeline unchanged. If cancellation arrives after the atomic restore has committed, sending is cancelled and the edited prompt remains as a draft. The writer lock is held until the restore worker has safely finished.

## Visible automatic context cap

- See the current **Auto cap** beneath context usage in the status bar, with exact retained-history tokens and the selected ceiling in its hover/keyboard tooltip.
- Follow reductions, larger trials and unchanged targets during backend memory waits. Direct chats and queued/remote runs publish the same request snapshot, available after tab switching or reconnecting to an active run.
- Finished runs show **Last auto cap**. A new run shows **Auto cap pending** until its own request is prepared; missing history or another model's metrics cannot supply a false live cap. The cap is a history target, separate from token usage and the full model context window.

## Backend-guided capacity recovery

- Retry the observed oMLX HTTP 507 model-load memory rejection after 2, 5, 10, 20 and 30 seconds. Keep the current prompt and the separate 24-attempt context-reduction allowance while waiting.
- Resume progressively smaller request views after a prompt-capacity rejection. Model-load allocations never become prompt-memory estimates or bytes-per-token samples.
- Send preserved instructions/latest input even when a rough local estimate is over budget; let the backend accept or reject the request. After a real rejection, stop if nothing else can be removed instead of replaying identical input.
- Show the latest failure, separate memory retry counts, and backend allocation figures. Stop remains responsive during waits; real partial output is never automatically replayed.

## Model choices and message settings

- Select the model and thinking level directly inside **Edit & replace timeline**. Model switches use that profile's thinking default and show supported choices; Cancel preserves current chat settings.
- Each input, Thinking, response and Tool bubble has a small information tooltip showing its recorded model and thinking selection. Tool bubbles identify the model that requested the tool.
- Historical settings remain stable after profile edits, model switches and page reloads. New queued inputs and follow-ups also record their run's settings. Missing legacy details are shown as **Not recorded**; Model default does not imply a specific thinking level.

## Target-aware coding in normal chat

- For writing, modifying or debugging code whose behavior depends on the target setup, establish the actual build/run system before choosing version-sensitive APIs or commands. Existing facts and relevant project files guide what needs checking.
- Inspect an accessible target directly, or offer concise read-only commands for the user's target OS/shell and accept the full pasted report in chat. Portable code, known setups and non-code tasks do not require an environment questionnaire.
- Instruct the model to consult official documentation for the installed version, investigate version errors before retrying remembered commands, and retain compact evidence with its target/source/date.
- Include UTC retrieval dates in web search/open results; cached Find retains the original date, with unknown dates for older cache records. Retrieval is distinct from publication and verification.

## Model defaults and test machines

- Choose the default model for new projects/chats separately from the profile being edited. Set default thinking per model; new chats and model switches inherit it, while existing saved chat choices remain intact.
- Use **Environments → Create VM Environment** for named local development/test guests. Choose the OS, architecture, resources, project-file access and network setting for each VM; no primary VM is required.
- Use brokered model commands, binary file transfer, and main-area Bash/PowerShell/ash, noVNC Desktop and LuCI Web UI tabs. Manage start/stop and full stopped-VM snapshots, including Windows firmware/TPM state.
- Match ARM64 or x86-64 to the host for acceleration, or choose the other architecture for CPU emulation. Windows requires matching installation media, Lima 2.2+, QEMU and swtpm. OpenWrt requires QEMU and e2fsprogs; it uses private NAT, pinned official images and a dedicated guest SSH key.

## Project files and chat attachments

- After a host file write, retry an inconclusive isolated-VM read without repeating the edit. Check the host still has the written bytes, require a stable matching VM hash, and stop on real mismatches or exhausted read attempts.
- Finished files stay in their canonical `Files/Project-<ID>` tree. The agent reports exact paths and the user can open or download them in Project Files.
- `attach_file` creates an immutable chat download only if the latest User request explicitly asks for a separate attachment or a direct single-file download. It is hidden otherwise; accidental calls make no copy.
- When the backend has not sent new visible Thinking, Answer or tool-call details, the activity line says “Generating next action”. Its recent call-wide tokens/second rate is evidence of decoder activity, not evidence that an Answer bubble is being withheld.

## Navigation and menus

- Chat, environment, file explorer/editor, terminal, memory, downloads and file history tabs use identifiable colors in light and dark themes; the active tab is more saturated and has a matching accent strip.
- One click on a sidebar chat opens its chat tab; double-click opens that project's Files folder. Selecting a chat, Project Files or a file opened from that project panel highlights the matching workspace and project. Closing an active tab and restoring a session keep the same selection behavior. A single click on a workspace row has no navigation action; double-click opens its Environment tab.
- Context menus separate navigation, organization, project information, file operations and destructive actions using horizontal rules. Conditional actions do not leave empty menu sections.

## Adaptive retained context

- Start Auto from the configured/observed context window, with no fixed 96K retention cap. Preserve output reserve, system/tool costs, actual runtime limits, and the safety margin.
- Calculate reductions from reported token capacity or predicted/allowed memory. Two comparable rejected requests can estimate fixed allocation and variable bytes per input token; incompatible observations fall back to the single-observation calculation.
- Reduce gradually from the current assembled history, using quantitative feedback when available and a bounded small step otherwise. Keep 1,024-token granularity, a 4,096-token floor, and at most 24 retries per request.
- After stable acceptance near the current target, all modes can try a small increase on a later normal request, within the selected ceiling and with at most 64 upward probes per job. Failed probes increase the cooldown. Eligible history can be restored from the transcript; a configured ceiling alone is never counted as a successfully tested size.
- Share budgeting, tuning, and error normalization across generic OpenAI-compatible, oMLX, Ollama, and llama.cpp transports. Use feedback actually present; keep ordinary crashes/model-load failures explicit and never silently reconfigure/restart a backend.
- Keep tuning state local to the job and show the calculation method and trial results in one updated Event. Presets, Custom, and Maximum set upper bounds for the same automatic tuning; saved values remain intact. Explain Custom adjustment beside its GUI field.
- Distinguish a confirmed oMLX synthetic abort notice from model output, including split content/reasoning deltas and stripped wrapper characters. Confirm the complete abort detail against the structured error; preserve unconfirmed text and prevent replay after real output.
- Treat missing dashboard activity as unknown, including queue/phase gaps, and let real protocol errors take priority over watchdog timeouts. Continue tracking a known oMLX request ID through overlapping jobs; return its measured progress to the watchdog and UI even when another job is cancelled. Keep bounded waiting for genuinely static prefill and privacy-safe progress diagnostics.
- Require actual same-workspace boot observations for VM restart claims. Static mount lifetime flags and model-server errors are not restart events or proof of a lost namespace.

## Responsive startup and recovery audit

- Start projects with large References without hashing or copying the entire reference library before inference. Observe filesystem changes separately from exact owned-project recovery snapshots.
- Show distinct startup stages and retain their timing and safe SQLite error labels in diagnostics.
- Preserve the actual latest file bytes when a pre-prompt checkpoint follows a post-run history revision.
- Release project writers on failed history-head lookup, pre-start finalizer cancellation, and repeated cancellation; stop and reap isolated workers even when cancelled during launch.
- Require a usable safety snapshot before replacing a file from File History.
- Restrict process listing, output polling, input, and stopping to the originating project; scope browser sessions to their project too. Read-only Project Access grants do not transfer control of processes.
- Preserve a competing destination file if an attachment-copy fallback loses an exclusive-create race.
- Treat single-string interview examples and audit fields as whole strings instead of character lists.
- Present WHY HARNESSYXO as a holistic product explanation, with shipped capabilities distinguished from future environment integrations.

## Persistent bubble bookmarks

- Right-click any saved User, Thinking, HarnessyXO reply, Tool, or timeline-event bubble and choose **Bookmark** or **Remove bookmark**.
- Completed live model responses and Tool results become bookmarkable as soon as their records are saved, while the agent continues. No elapsed-time or action-count threshold applies. A currently streaming, unsaved response remains unavailable until that model response is stored.
- Show bookmark icons inside purple event menus and Browse all. Every user prompt retains its grey square, including bookmarked prompts, and is never duplicated.
- Jump to the exact bookmarked bubble, including Thinking versus final reply and later alternating output segments within one saved assistant message. Off-window bookmarks use the bounded virtual-history locate transaction keyed by their real source message.
- Persist bookmarks as project presentation state without adding them to model context, exports, memory, or instructions.
- Delete bookmarks automatically when their owning messages are removed. **Undo latest rewind** restores bookmarks together with the abandoned transcript, and archive snapshots record them.
- Keep workspace schema 14 through an additive compatible table; settings schema and inference-backend behavior remain unchanged.

## Responsive post-run history finalization

- Treat the model's terminal answer and its exact post-run file/memory revision as two explicit lifecycle boundaries. The answer releases the foreground run and **Stop** button without waiting for storage history to finish.
- Publish the revision in a lower-priority isolated Python worker, keeping filesystem scanning, hashing, and Git staging out of the WebUI interpreter. macOS and Linux receive best-effort native background/I/O priority hints without making either platform utility mandatory.
- Retain the same project/dependency-family mutation lease until publication completes. A related prompt waits safely before reserving a global model slot; unrelated projects can continue.
- Add one durable **Saving project history** Event only when finalization exceeds five seconds, then update that same Event to success or red failure. Fast saves create no extra timeline card.
- On application shutdown, terminate the isolated worker process group instead of leaving Ctrl+C blocked behind an unkillable checkpoint thread. Partial private history work is never published as a completed revision.
- Find the final transcript head with one indexed lookup rather than loading and deserializing the complete long chat.
- Preserve exact history, File History, upstream-baseline, workspace schema 14, settings schema 14, and inference-backend-neutral behavior.

## Fast, exact historical checkpoints

- Keep the pre-turn checkpoint on every accepted User prompt so **Edit & replace timeline** can still restore canonical files, project Git state, memory, task state, and linked attachments to the exact pre-turn boundary.
- Reuse the previous shadow commit when the persistent Git index proves that the ordinary working tree and scanned path set are unchanged.
- Stage changed ordinary trees with one compact include/exclude pathspec instead of passing every file to Git as a separate pathspec. Preserve visible files inside nested repositories while excluding their private `.git` metadata.
- Reuse an immutable large-file object after metadata-only changes only when bounded sampling first matches and a byte-for-byte comparison then proves the complete file is identical.
- Record privacy-safe scan, large-file, project-Git, and shadow-Git stage timings in diagnostics without recording project paths or contents.
- Remove accepted pasted/file attachment chips from the composer as soon as the backend marks them sent, including in a browser which reattached during a long run.
- Keep workspace schema 14, settings schema 14, and all inference-backend behavior unchanged.

## Complete read-only Project Access context

- Make an explicit Project Access grant cover live canonical files, saved chat history, history-linked attachments, model-visible memory, and Current Task State.
- Keep shared memory and task state retrieval-first instead of injecting another project's content into every request. Use `read_project_memory`, `get_task_state`, or `search_upstream_memory` with a source project ID only when relevant.
- Label every shared-state result with its source Project/Chat, relationship, read-only status, current revision, volatility, and secondary-project authority boundary.
- Treat shared state as belonging to another Project/Chat entity. It is not inherited instruction text, `Files/References`, vendor/user-provided material, or external ground truth.
- Tell the model to preserve only the source-labelled facts or artifacts its own project must retain across source edits, access revocation, or archival; nothing is copied automatically.
- Keep grants direct, non-transitive, immediately revocable, backend-neutral, and serialized against concurrent source mutation. Unsent attachment drafts and unrelated projects remain private. Workspace and settings schemas remain 14.

## Cross-project provenance boundary

- Tell every model at run start that `Files/References` is the shared reference-library location, while every `Project-<ID>` is a HarnessyXO project working/artifact tree.
- Classify Project Access material as secondary work created or collected by a separate Project / Chat entity—not vendor/user-provided input, original vendor material, vendor truth, or primary evidence by default.
- Define the natural-language rule explicitly: asking the model to consult a Project-<ID> “for reference” changes relevance only; it does not change provenance, authorship, authenticity, or authority.
- Treat read-only as a permission boundary only. A model may reclassify a specific file only from an explicit file-origin statement or traceable file-specific provenance.
- Repeat the boundary in `list_project_access`, `list_files`, `read_file`, `get_file_fingerprint`, `search_text`, and shared-history retrieval results so it survives tool-driven investigation as well as long reasoning runs.
- Keep search results compact by returning provenance once per matched path instead of duplicating the full notice on every matching line. Workspace and settings schemas remain 14.

## Visible Project Access in the sidebar

- Show a compact green **Read: XXXX, YYYY +n** badge beside a destination project's own ID whenever it has direct external Project Access grants.
- Keep the first two source IDs visible without widening the sidebar; use `+n` for further sources and ellipsis only when the available row width is smaller still.
- Show every source title and public ID in the badge and project-row tooltips, explicitly labelled **External Project Access · read-only**.
- Omit the badge entirely for projects without direct grants and for archived projects whose live grants were revoked.
- Load all active sidebar grant labels in one database query instead of issuing one query per project row. Workspace and settings schemas remain 14.

## Explicit Project Access and hierarchy editing

- Add **Project Access…** to every active Project / Chat right-click menu, with one checkbox per other active project.
- Expose checked sources as live read-only canonical file trees, bounded source-labelled saved-history retrieval, and attachments linked from saved history. Never expose another project's unsent attachment drafts.
- Keep access direct and non-transitive. Descendants do not inherit grants, and parent transcripts remain private unless the parent is explicitly checked.
- Add `list_project_access` plus `source_project_id` routing for history and attachment discovery. Shared historical images can be deliberately reactivated for the next vision-capable model step.
- Show direct grants in Project Files at `/workspace/Files/Project-XXXX` with a **Project Access · read-only** marker. Unrelated and ungranted projects remain hidden.
- Project access is enforced in structured paths and a retained VM mount namespace. Every shared bind is remounted read-only and included in namespace identity/probes, so access changes take effect without restarting the VM.
- Add **Make child of…** and **Unchild**. Reparent only the selected project's incoming edge while retaining its complete descendant subtree, canonical directories, IDs, histories, files, memory, and descendant edges.
- Reject cycles and obstructed mountpoints; require the moved subtree to be idle and unlocked; preserve sidebar pin anchors.
- Serialize a Project Access destination with its direct sources to prevent live reads from interleaving source mutation. Archive revokes live grants while preserving their former rows in the sealed database snapshot.
- Keep the implementation inference-backend neutral. Workspace schema remains 14 and settings schema remains 14.

## Authenticated LAN access by default

- Bind new installations to `0.0.0.0:6767` by default, while continuing to print a loopback Local URL and a detected LAN URL at startup.
- Migrate only the exact former schema-13 factory endpoint `127.0.0.1:6767` to the new LAN default. Customized addresses or ports are preserved.
- Make the migration one-time through settings schema 14. A user who selects `127.0.0.1` afterward keeps that explicit local-only choice on later loads.
- Keep username/password authentication mandatory on every interface, retain same-origin mutation checks and authenticated Socket.IO/API access, and continue warning that plain HTTP is appropriate only on a trusted LAN.
- Keep `127.0.0.1` available in **Settings → Server / Network** for local-only deployments, and require an application restart after bind changes.
- Workspace schema remains 14 and settings schema advances to 14. The bind policy is independent of the configured inference backend.

## Shared-Linux and DGX startup correction

- Create the machine `.settings` directory with explicit private `0700` permissions, even when the host uses a collaborative `umask 0002`.
- Safely tighten an existing group-writable settings directory only when it is a real directory owned by the current OS user. The repair uses a non-following directory descriptor rather than a path-based chmod.
- Validate the login settings root before `MachineStore` can read or create state. Wrong-owner paths, symlinked roots, linked credential files, and permissive credential files remain fail-closed.
- Prepend the verified release-local `.vendor` directory before the launcher's optional host-prerequisite check, eliminating a false `No module named 'httpx'` warning when dependencies are already installed.
- Keep the application entry point's independent `.vendor` setup and the Create/Start prerequisite recheck. Workspace schema remains 14 and settings schema remains 13.

## Correct child-parent namespace validation

- Validate retained project views from both the keeper's mount namespace and its PID namespace, matching the namespace pair used for actual Tool commands.
- Let `mountpoint(1)` read the keeper's own `/proc/self/mountinfo`, so a nested same-filesystem parent bind is no longer falsely reported as `ANCESTOR_MISSING`.
- Change the retained-view revision so the first Tool call after upgrading replaces an older v0.6.12 keeper automatically; no workspace-VM stop or restart is required.
- Keep v0.6.12's bounded pre-command repair and fail-closed safety checks. The requested command still cannot execute until the owned project, References, every ancestor, and hidden backing-root invariants pass.
- Surface the allowlisted controller and failed-probe codes together in Tool results and privacy-safe diagnostics, while continuing to redact command output and user paths.
- The fix is entirely in the workspace/VM layer and remains independent of oMLX, Ollama, llama.cpp, or any inference backend. Workspace schema remains 14 and settings schema remains 13.

## Automatic child-workspace view repair

- A new child Project / Chat no longer needs a manual VM restart when its retained project namespace fails its first post-start validation.
- HarnessyXO rebuilds and revalidates the isolated namespace up to three times before allowing the model-requested command to execute.
- Each rebuild receives four bounded validation polls, covering short host-to-VM mount-visibility and namespace-readiness races without duplicating a model command.
- The probe verifies the owned project, References, every live parent/ancestor mount, and continued hiding of both private backing roots.
- Exhausted recovery remains fail-closed and now retains a precise probe-stage diagnostic. Different-byte mapping or file observations are never retried.
- Repair is entirely in the workspace/VM layer and has no dependency on oMLX, Ollama, llama.cpp, or any inference backend. Workspace schema remains 14 and settings schema remains 13.

## Persistent per-chat composer drafts

- Every Project / Chat owns an independent unsent message draft. Chat A cannot overwrite or inherit Chat B's text.
- Switching between chat, file, terminal, environment, memory, or export tabs captures the exact composer value before the active panel is rebuilt and restores it on return.
- Drafts are stored in the workspace database, so a browser refresh/page recreation restores the active chat's message box without adding anything to the transcript or model context.
- A successful normal send, queued follow-up, or persisted global-queue submission clears that chat's draft. Validation failures leave it intact.
- Closing a chat tab with text asks **Discard unsent message?**; **Keep editing** preserves it and **Discard and close** clears it. Project deletion also removes the private draft state.
- Draft persistence is UI/workspace behavior and remains completely independent of the inference backend. Workspace schema remains 14 and settings schema remains 13.

## Hot-adjustable retained context

- Saving **Retained live context** is picked up by an already-active interactive, queued, or remote job before its next model request or adaptive prefill-memory retry.
- An in-flight prefill/generation is never interrupted or mutated. The current request finishes under its original payload, then the following safe boundary applies the change.
- Only retained-context mode and Custom tokens are hot-loaded. Model identity, endpoint, credentials, sampling, Thinking controls, output limits, and all unrelated settings remain the immutable run-start snapshot.
- A changed target creates one new cache-stable context epoch from the authoritative saved transcript. Lowering can compact the view; raising can restore eligible history. Saved transcript, memory, task state, attachments, and Project Files are untouched.
- An indigo timeline event confirms the old and new effective target when the active run actually adopts the saved value.

## Progressive prefill-memory tuning

- Recognized prefill-memory failures trigger a bounded sequence of progressively smaller run-local retained-history targets. The client normalizes both `prefill_memory_exceeded` and `prefill_memory_aborted` into this shared recovery condition, including HTTP errors and streaming error objects. A narrow fallback also recognizes the backend's explicit mid-prefill memory-guard wording when a stream omits the code.
- Each target uses 1,024-token granularity. Reported token limits or estimated/allowed bytes inform a bounded gradual reduction from the currently assembled history. Missing feedback uses the same small-step bound.
- Tuning starts from the history actually assembled, not merely a larger configured Maximum/Custom ceiling, so a small memory overage does not cause an unnecessary large context loss.
- Up to 24 capacity retries update one amber card. The card distinguishes estimated whole input and history, measured backend input when supplied, and the selected target. Stable acceptance can allow gradual upward reassessment in all modes. Exhausted tuning remains a red terminal result with attempted targets visible.
- Retry accounting belongs to the current model request, not the age of the whole agent run. If reasoning, answer text, or tool-call fragments have already been delivered for the failing request, automatic replay is disabled.
- The adaptive value is run-local and never silently overwrites the model profile. Manual Save remains authoritative at the next safe boundary.
- The mechanism is backend-neutral and activates only on the exact normalized error condition. No logic depends on a model name or requires oMLX, Ollama, llama.cpp, or another specific server.
- Workspace schema remains 14.

## Transient workspace-verification recovery

- A fresh host mapping nonce is durably written once and kept alive through a bounded four-attempt verification window spanning 1.1 seconds of backoff.
- Only inconclusive nonzero probe executions without a structured projection error are retried. This handles brief shared-filesystem directory-entry visibility lag without weakening the safety boundary.
- A zero-exit probe containing different bytes is an immediate `WORKSPACE_MAPPING_MISMATCH`; an exact host/VM file digest mismatch remains an immediate `FILE_VIEW_MISMATCH`; structured projection failures and timeouts remain terminal.
- The final Tool receipt records attempt count, transient failures, and whether the probe recovered. Probe files are still removed before any model-requested command executes.
- A saved workspace-safety terminal answer now says **Blocked after …** in red instead of incorrectly saying **Completed in …**.
- `copy_attachment_to_project` remains byte-exact, non-overwriting, and private-source-preserving. A successfully recovered probe proceeds to the existing independent whole-file SHA-256 and byte-count comparison.
- The retry policy lives in the generic workspace-verification layer and does not depend on oMLX, Ollama, llama.cpp, Lima-specific model behavior, or any inference backend.
- Workspace schema remains 14.

## Replace historical prompt attachments

- **Edit & replace timeline** keeps its original-attachment checkboxes and adds **Add replacement attachment** for corrected or additional files.
- New files use a dialog-token-owned private staging status. They are invisible to the ordinary composer and cannot leak into an unrelated send.
- The rewind validates file ownership, path, type, registered size, and stable filesystem identity before and during the atomic replacement transaction.
- A successful replacement promotes the selected originals plus new files to the edited prompt's pending attachment set, then sends that prompt in the same Project / Chat.
- Cancel, upload-time cancel, file removal, and pre-commit rewind failure clean only that dialog's still-staged files. A cleanup racing a successful commit cannot delete promoted attachments.
- **Undo latest rewind** restores the exact abandoned attachment registry and does not resurrect files introduced only by the replacement dialog.
- Workspace schema remains 14.

## Bounded attachment retrieval and deliberate Project import

- `search_attachment` defaults to four 4,000-character chunks and enforces a 24,000-character aggregate content ceiling even when an older/model-generated call asks for 12 × 12,000.
- A lexical miss returns no unrelated beginning/evenly-spread samples. The model receives precise refinement guidance instead of a large pseudo-result.
- `read_attachment` is one bounded exact range with a 32,000-character ceiling; legacy 200,000-character calls are safely clamped and reported as such.
- Compacted attachment Tool results retain the attachment ID, query, useful range/count coordinates, and a direct reminder that the saved attachment remains intact.
- Repeated identical attachment searches can enter evidence-driven temporary retrieval retention, just like exact ranged reads.
- `copy_attachment_to_project` explicitly materializes an attachment for grep/parser/VM work without exposing HarnessyXO's private path. It requires both attachment and filesystem-write permissions.
- Project imports preserve the private original, never overwrite an existing file, enforce the owned-project boundary, detect source changes, clean cancellation residue, and return byte/SHA-256 plus host/VM verification receipts.
- Ordinary attachment inspection never creates or contaminates Project Files.

## Backend-neutral inference resilience

- One provider-neutral watchdog covers generic OpenAI-compatible, oMLX, Ollama, and llama.cpp streaming paths.
- A 30-second no-progress boundary triggers only a read-only health check and live status; it does not cancel or retry healthy long prefill work.
- Initial prefill/model startup keeps a conservative 600-second silence allowance. Once output starts, the no-progress ceiling is 120 seconds.
- Provider adapters can supply stronger evidence, but generic fallback behavior is always present. oMLX request disappearance requires two exact request-ID confirmations.
- Abandoned waits preserve partial Thinking/answer output, record a red timeline event, and never automatically replay a generation or Tool call.
- Evidence-triggered tuning reminders use active profile values. A 32,768-token maximum output produces a 16,384-token oMLX Thinking Budget suggestion while leaving settings untouched.
- The permanent local-LLM-first/backend-agnostic boundary is documented and regression-tested.

## Denser compact timeline

- Compact Thinking, Tool, and Event rows are cardless, approximately one paragraph line high, and closely stacked around the full transcript.
- The horizontal rule, animated running ellipsis, click-to-expand behavior, and red failed Tool/Event text remain.

## Explicit Project / Chat export contents

- Checkbox rows independently include or exclude User prompts, main responses, intermediate responses, Thinking, Tool calls/results, and referenced attachments.
- Intermediate responses, Thinking, and Tool activity each choose Original text, AI summary, or deterministic Counts only.
- The default selections preserve the former Level 3 behavior without exposing bundled “X + Y” labels.
- Generated project handover is a separate export type with its own length control.
- The summary-model selector appears only when the chosen export actually needs inference.
- Raw metadata is permitted only with a complete Original-text transcript, so excluded content cannot leak back through metadata.
- Legacy numeric levels still map to their original renderer contracts for compatibility, while new Markdown records every explicit selection.

## Timeline visibility and operational events

- Three **Show** pills above the composer independently switch Thinking, Tools, and Events between full cards and one-line compact rows.
- Compact rows retain the activity name, running/completed/failed state, duration where available, and a horizontal rule; active rows animate a stable-width ellipsis unless reduced motion is requested.
- Prompts and final HarnessyXO answers always stay fully visible. Clicking one compact row temporarily expands that card without changing the saved global choice.
- Display choices persist for the signed-in username in that browser and preserve transcript follow/scroll anchors when changed.
- Context-compaction cards explain why a retry happened, estimated tokens before and after, the recovery target, and the prefill memory estimate/ceiling. They explicitly confirm that saved chat, memory, task state, attachments, and Project Files were not deleted.
- Automatic continuation, long model-slot waits, and safety-blocked runs are durable timeline events with distinct indigo, neutral, and red treatments.
- Timeline events are UI-only records: they never enter model requests, context/token budgets, or chat exports.
- **Edit & replace timeline** and **Delete prompt & everything after** appear only for exactly one persisted User prompt. Deletion confirms the boundary, stops this chat's work, cancels its queued prompts and restores pre-prompt files, memory, task state, attachments and conversation without sending a new model request. **Undo latest rewind** restores the deleted branch. Routine output-route icons are hidden; real route warnings remain concise and full telemetry lives in Run Stats/diagnostics.

## Persistent project execution view

- One isolated mount/PID namespace per active project is retained for the lifetime of the running workspace VM.
- A successful model-created mount remains visible across later Tool calls in that project instead of disappearing after each command.
- Each command mechanically restores and verifies `Files/Project-XXXX` as its real cwd after login profiles run.
- References and ancestors remain read-only; unrelated projects and controller-private state remain hidden.
- A rewind or other project/ancestor root replacement changes the view signature and safely recreates the namespace so stale directory inodes are never pinned.
- VM stop/rebuild ends runtime mounts; explicit unmount remains available inside the project.

## Canonical project files

- One writable `Files/Project-XXXX` directory per project/chat.
- One shared, human-managed `Files/References` directory, read-only to every LLM.
- Four-character non-confusable IDs, unique per workspace and preferring unused first characters.
- Project title, ID and current/queued status form one sidebar selection target.
- Explorer title annotations do not alter real folder names.
- Human explorer, structured tools, Git/LSP, and VM commands use the same canonical bytes.
- Chat **Project Files** opens at `/workspace/Files` but exposes only `References` and the current `Project-XXXX`; live ancestors use nested model-visible paths and unrelated sibling projects stay hidden.
- No active private working copies and no separate output folders.
- Final deliverables, source, research, and intermediate work remain together in the owning project.
- Uploaded archives extract into the owning canonical project without switching to a hidden working root.

## Live project dependencies

- **Create child project** creates a fresh chat, empty owned directory, and fresh owned memory.
- Children see current parent/ancestor files and durable memory live and read-only.
- Parent transcripts, hidden reasoning, files, and memory are not copied into the child.
- Unrelated projects are invisible to model tools.
- Managed virtual directories and VM bind projections enforce upstream read-only access without unsafe host symlinks.
- Dependency cycles are rejected.

## Lazy upstream reconciliation

- References and ancestor file manifests are compared when a run actually starts.
- Durable upstream memory heads and entries are compared at the same boundary.
- A private consolidated added/modified/removed delta is supplied only when current state changed.
- No persistent stale badge or manual refresh workflow.
- A baseline advances only after a successful run against stable upstream state.
- Child memory retains provenance and is reconciled rather than blindly deleted or overwritten.
- Generic memory kinds work across software, research, writing, analysis, and other domains.

## Rewind and recovery

- Parent rewind affects only the parent's chat, owned files, and owned memory.
- Active children, their content, and queued prompts survive unchanged.
- **Edit & replace timeline** restores the pre-prompt revision and replaces later active history.
- **Undo latest rewind** restores the abandoned canonical files, messages, memory, and checkpoint links.
- The active root always remains the canonical project directory; history never becomes a working tree.
- External real-world side effects are explicitly outside rewind guarantees.

## File History

- Persistent application tab rather than a transient history modal.
- Left-side distinct versions with timestamps, presence state, and prompt/project provenance.
- Right-side preview, metadata, and current/previous comparison.
- Exact-version download, restore-as-copy, and replace-current with a safety snapshot.
- Browse paths that are currently deleted.
- Private history is not visible to the model or mounted into its VM.
- A busy history lock cannot block sign-in indefinitely. Opening a workspace reports the contention immediately; other history actions bound lock acquisition to ten seconds. Retry after the active operation finishes. Existing history, files and lock holders are preserved.
- Keep unavailable saved tabs in their original positions with a persistent error and **Retry workspace**. Retrying reloads and validates them again, including when another workspace restored successfully.

## Permanent family archive

- Archiving any project permanently seals its complete active descendant subtree.
- Family hierarchy, chats, files, memory, relevant upstream/reference snapshots, and queued-run metadata are retained read-only.
- Archiving a middle child leaves its active ancestors and siblings in place.
- Archived IDs remain reserved.
- Archived roots can be reordered within Archives without crossing into Active.
- **Delete archive family** permanently removes the complete sealed root and every archived descendant as one unit.
- No Unarchive operation and no Archive-to-Active drag path.

## Global agents and queues

- One normal setting—**Global Agent Slots**—limits coordinators plus temporary subagents.
- One slot guarantees complete finish-then-next overnight queue execution.
- With multiple slots, unrelated projects can run in parallel.
- Parent and descendant projects always serialize.
- Blocked related work does not prevent an unrelated queued project from using capacity.
- Sidebar global queue positions, active/running badges, queue cancellation, and stop controls.
- Keep the complete queued prompt and queued attachment names visible in its chat across tab switches and page refreshes until the real saved User message appears. A failed start before the prompt is saved leaves a dismissible prompt notice; queued text stays outside model context while waiting.
- Choose Auto for any free slot or pin a queued coordinator to a specific Global Agent Slot. Other independent jobs still fill free slots. Persist the choice and release pins to removed slots when the global limit is reduced.
- Footer `Agents: active / limit` status with active coordinator/subagent detail.
- Verbal delegation through a bounded read-only `delegate_task`; no per-message agent-count selector.
- One-slot coordinator suspension/slot transfer and multi-slot subagent priority.
- Advanced per-profile backend request capacity remains a separate physical/API ceiling.

## Inspectable timing

- Clickable **Completed in …** control on final answers.
- Full-run wall time, queue wait, slot wait, model time, Tool time, Thinking/answer phases, tokens, TTFT, cache, speed, and configured cost.
- Per-subagent time, wait, tokens, and completion status.
- Wall-clock and summed agent time remain distinct.

## Files, delivery, and packaging

- Direct single-file downloads preserve exact bytes.
- ZIP creation occurs only after explicit packaging/export intent.
- Packages are written into the owning canonical project directory.
- Packaging is off the UI loop, cancellable, and cleans partial files.
- Whole-file fingerprints and operation receipts support consistency diagnostics.
- Double-click Up navigation and NiceGUI-safe context menus.

## Workspace ergonomics

- Dependency-tree sidebar with live-parent indicators.
- Pin fixes the current relative position and replaces the grab handle.
- Lock protects owned chat/files/memory while preserving child creation.
- One fixed-size segmented Send/queue control with no overlapping button geometry.
- Queued composer prompts retain model, Thinking choice, and reserved attachments.
- Draft composer text persists until sent or deliberately cleared.
- Compact Thinking/activity display and mechanical Thinking/Answer output provenance.
- Transactional instruction-interview answers: malformed model JSON leaves the question and exact multiline answer editable for retry.
- Compact instruction dialog with bounded model selector, one collapsed answer-history section, and internally scrolling text areas.
- Larger question number and question text below the divider following **Ready for your answer.**
- Stable page-owned operation dialogs with progress and elapsed time for archive sealing/deletion.

## Accounts and access

- First-browser administrator setup guarded by a terminal-only one-time code.
- Persistent username/password login; no per-launch token URLs.
- Native **Settings → Users / Password** management.
- Add, disable, reset, delete, and change-password controls with reauthentication and last-admin protection.
- Any non-empty password length is accepted.
- Shared light/dark HarnessyXO theme across setup, login, and application UI.
- A timed-out password check reports a temporary sign-in failure, with separate diagnostics for accepted and rejected credentials and subsequent workspace loading.
- No automatic browser launch.

## Notifications

- ntfy success/failure/stopped alerts with no required account or inbound port.
- Locally rendered subscription QR, generated secret topic, and test notification.
- Optional interactive commands for reading model answers, browsing earlier replies, checking run statistics and replying to the selected chat.
- Editable command names and individual On/Off switches in **Settings → Notifications**, with a help preview. Command names start with `.`, `/` or `!`; help uses the current names and enabled actions. Ordinary messages are ignored.
- Delivered alerts carry a selection code. Start with the newest alert, select another with `.use CODE`, and keep that selection when later alerts arrive. Routes expire after the configured reply window or an app restart.
- `.read [number]`, `.prev`, `.next` and `.more` read saved answer text in small pages. `.replies [page]` lists answers since the selected alert's prompt; `.history [page]` lists earlier answers across that chat. Exclude thinking, raw tool calls and explicitly marked app error/status messages.
- `.stats` reports visible-answer counts, recorded main model calls, available token/cache/speed measurements and run elapsed time. Keep missing counters unavailable and distinguish main-call totals from full run time.
- `.reply text` sends the text to the selected chat through the normal follow-up queue and tool permissions. Only the configured, enabled reply command can send a prompt; old plain-message settings have no effect. Retired command names, disabled commands and unknown commands never become model prompts.
- Error reasons with exact-run RETRY/STATUS codes, source/model/attachment validation and duplicate protection.
- Preparation/queue/retry updates, one confirmed Running again alert and quiet recovered completion.
- Brief automatic GPU/memory recovery notifications; active backend requests are not offered for remote replay.
- Safe active-run follow-up queue and normal idle-run start.
- Outcome alerts stay brief. Reading commands explicitly send saved answer content through the configured ntfy server; anyone who knows the secret topic can use the enabled commands. Keep the master inbound switch off when remote access is unwanted.

## Tooling and isolation

- Structured read/write/search, shell/process, Git, LSP/code intelligence, web, browser, attachments, memory, diagnostics, and external-target tools.
- Layered tool permissions with Allow/Ask/Block behaviour.
- Persistent per-project VM namespace containing only own writable files plus read-only References, ancestors, and explicitly granted Project Access sources.
- Private `.settings`, history, archives, and unrelated/ungranted projects remain outside model-visible roots.
- External SSH target broker with bounded operations, dedicated `/root/` subdirectories for root targets, and host-side password or key authentication. The command filter is not a root security boundary.
- Long-context assembly, prompt-cache observability, attachment retrieval, and durable run/task state.

## Compatibility boundary

- v0.6.x requires a fresh workspace schema.
- v0.5.x workspace layouts are rejected without mutation; they are not migrated.
- Existing release-local settings and account records can be retained.

## UI usability

- Compact target management with search, target-type filtering, and expandable access/activity details.
- A searchable OS catalog with per-guest resource defaults and relevant installation fields.
- Settings section selector on narrow windows; stable header/footer and scrollable settings content.
- Scrollable form dialogs, wrapping long names, and model profile controls that fit smaller windows.
- Keyboard-operable sidebar section headings, accessible names for icon controls, and reduced-motion support for navigation and file transitions.

## Why HarnessyXO

<!-- Current release: v0.6.83 -->

Capacity recovery follows backend feedback: a prompt rejection reduces the request view, while the observed model-loading memory rejection gets delayed retries with the same prompt. A rough token estimate does not prevent preserved input from reaching the backend, and the timeline identifies which recovery is active.

HarnessyXO is a workspace for work that outlives a chat: investigating an unfamiliar system, building software, analysing firmware, or developing related projects over days and weeks. It brings the model, project files, Linux environment, durable knowledge, and recovery controls into one place you can inspect.

Its strongest reason to exist is the way those pieces fit together. You can give an agent a real working environment, see exactly which files it owns, let another project consult its work, and revisit an earlier decision with the corresponding files and memory restored.

### One canonical home for project files

Each project/chat has one `Project-XXXX` directory. The file explorer, structured file tools, and project view inside the VM operate on those same files. The script you inspect is the script the agent runs; its deliverables stay beside its working material.

The shared `References` directory provides a separate home for material you supply. Models can read it but cannot write to it. HarnessyXO's database, history objects, uploads, and internal recovery records stay outside the model-visible file tree.

This is useful when the work includes disk images, captured traffic, documents, binary samples, experiments, and reports as well as code. An attachment can remain private chat material or be deliberately copied, byte-for-byte, into the project's files when the agent needs a parser or command-line tool to analyse it.

### An environment you can use alongside the agent

HarnessyXO manages Linux workspace VMs and tool provisioning. Choose an image and a Minimal, General Development, or Reverse Engineering tool bundle, then use the integrated terminal and file explorer to inspect the environment yourself. Ubuntu is the established default; the catalogue also exposes experimental Debian and Fedora integrations.

The reverse-engineering bundle supplies foundations for inspecting binaries, filesystems, and firmware, with optional tools available through environment controls. Setup and supported VM snapshot operations are part of the workspace workflow.

Project commands use retained, isolated mount and process namespaces. The current project is writable; References, live ancestors, and explicitly granted source projects are read-only. Unrelated projects and HarnessyXO's private state are excluded from the agent's normal execution view.

You can inspect a failing command in the VM terminal, check its output in the explorer, and continue the project conversation. The environment remains available for human investigation as well as model tool calls.

These are CPU-based VM environments. OpenWrt has its own guest and file integration. Windows uses experimental Lima support, your installation media and separate deployed project copies. Raspberry Pi board emulation is not implemented.

### Local VMs and external targets

Create named local VMs under **Environments → Create VM Environment**, then tell the model which VM to use for building or testing, or let it choose among enabled VMs. Shared project source stays in the workspace while each VM keeps its own system and dependencies. Separate-copy guests receive explicit deployments and require deliberate artifact collection.

**External Targets** links existing SSH machines and devices. External access and selected-action controls apply to those connections independently of local VM use. Supported local terminals and graphical consoles open as main-area tabs. Stop a VM and take a snapshot before disruptive guest experiments; canonical workspace source is separate from VM rollback.

### Projects that can depend on other projects

A **child project** starts with its own conversation, memory, and writable directory, while retaining live read-only access to its parent's files and knowledge. It represents a dependency: an implementation can depend on a protocol investigation, or a report can depend on an analysis project.

**Project Access** lets you choose other projects that a project may consult. A visible **Read: XXXX, YYYY** indicator shows its direct grants. These expose the selected project's current files, saved history, linked attachments, memory, and task state through read-only tools. Access is direct and is not automatically passed to descendants.

The model receives a useful distinction: another project's conclusions are source-labelled working knowledge. Being read-only does not turn them into vendor documentation or prove their claims. Shared material remains live and can change; the agent is told to preserve the particular evidence its own work depends on.

Before a child continues, HarnessyXO checks upstream file observations and memory against its last successful baseline. Changes tell the agent where to look again. Rewinding a parent leaves the child intact; on its next turn, the child must reconcile its work with the parent's current state.

This makes it practical to separate investigation, implementation, testing, and reporting while retaining explicit relationships between them.

### Retry a decision with its working state restored

Completed model/tool groups can become visible **State saved** points. Right-click a marked bubble to restore its matching conversation, files, memories and task state, then continue the original task. A saved transcript entry alone does not qualify: the coordinated checkpoint must be complete and available. This allows a long investigation to resume from completed progress after a failure, while keeping its original request and evidence in history.

**Edit & replace timeline** operates at a user-prompt boundary. It coordinates the selected project's conversation, files, supported project Git state, memory, task state, and attachment links. You can change the replacement prompt's attachments, model and thinking level in the same dialog.

An incorrect assumption can spread into a parser, an analysis file, and a remembered conclusion. Restoring the coordinated state lets the next attempt start from the selected decision point.

Recovery history is private and separate from the project's normal Git repository. It captures supported files in the owned project, including changes made through shell commands. Large files use immutable stored objects, with copy-on-write support where the filesystem permits it. **Undo latest rewind** provides a recovery path for the abandoned timeline and files.

**File History** lets you inspect known versions, compare content, download an exact version, restore a copy, or replace the current file after a usable safety snapshot. These controls work for code and non-code investigation material.

The scope matters: recovery cannot reverse actions already performed on an external device or service. References are observed at startup using filesystem metadata; that observation is not a byte-exact backup. Automatic turn checkpoints protect the owned project. Previously saved reference versions, explicit restore safety snapshots, and sealed archive contents retain their own recovery roles.

### A workspace that carries its project history

Workspace-owned files and state stay together, including chats, attachments, memory, recovery history, and environment configuration. This provides a concrete unit to back up or relocate instead of scattering evidence across chat exports and unrelated directories.

Stop the application and VM before moving the whole workspace, preserve its private state as well as `Files`, and reopen it on a supported host. Host registrations, accounts, credentials, and compatible VM architecture still matter; folder portability does not imply live machine migration.

Completed work can be sealed with **Archive**, which records a project family and supporting state. Archives remain browsable, can be organised within Archives, and can be deleted. Archiving is permanent; archived projects cannot be returned to active work.

### Turn a goal into durable working instructions

The instruction interview asks one substantive question at a time, considers higher-level instructions and available reference context, and produces an editable instruction draft.

It helps settle decisions before a long run: what success means, what must be preserved, what evidence is required, how much autonomy is appropriate, and what should be delivered. Discoverable facts can be delegated to the agent instead of becoming repeated questions about filenames and mount points.

Instructions, durable memory, and current task state have separate roles. Instructions describe how to work; memory retains findings and decisions; task state records the current objective and next action. Their relationship to project access and rewind makes them useful across long investigations.

### Long jobs you can follow and schedule

Persistent project queues and one **Global Agent Slots** limit coordinate competing work. Setting it to one lets a local model work through queued projects sequentially. Related project writers are coordinated so their state does not silently interleave.

Each sidebar project keeps its name, identity and live status in the same selectable row. Active slots, pending requests and replacement waits remain attached to the project they describe; idle projects stay compact.

The interface distinguishes Thinking, tool activity, context compaction, startup stages, and post-run history saving. You can compact busy timeline sections while retaining visible failures, then use prompt navigation and persistent bubble bookmarks to return to the exact evidence you need.

Message information tooltips preserve which model and thinking setting belonged to each input or output, even after switching models. Missing information in older records is marked explicitly.

Saved conversations survive changes to active model context. Context controls and cache-aware prompt construction help work within a local backend's practical limits, while memory and task state support continuity. Completion notifications make unattended queues useful without requiring the chat to remain on screen.

### What makes the combination distinctive

Individual capabilities overlap with other harnesses. [Claude Code documents conversation/code checkpointing](https://code.claude.com/docs/en/checkpointing), [Aider integrates commits and undo with Git](https://aider.chat/docs/git.html), and [OpenCode provides configurable permissions](https://opencode.ai/v2/docs/permissions). A rewind button, local endpoint, or permission switch alone is not an exclusive feature.

HarnessyXO's case is the combined workflow:

| When your work needs… | HarnessyXO brings together… |
| --- | --- |
| A persistent place to investigate | Managed Linux VM, tool bundles, terminal, and canonical project files |
| Projects that build on each other | Live dependencies, selective Project Access, source-labelled memory, and ownership boundaries |
| Recovery after a mistaken direction | Prompt-boundary restoration of files, conversation, memory, task state, and attachments |
| Continuity across long local-model jobs | Persistent queues, shared concurrency control, saved history, context controls, and visible operational events |

Choose it when managing the environment, evidence, project relationships, and recovery is a substantial part of the work. That is where HarnessyXO's integrated workspace offers its clearest advantage.
