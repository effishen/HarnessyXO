# VM files and live access

This is the file-access contract for every HarnessyXO VM provider. A new guest
OS or transport must use the shared project policy and declare its supported
file modes. It must report an unsupported mode instead of quietly exposing a
larger directory, omitting required sources, or falling back to the host shell.
The project and References policies live in `harnessy.core.project_mounts`;
runtime changes go through
`harnessy.environment.file_views.FILE_VIEWS`. Provider transport code consumes
that plan. It must not invent its own hierarchy or Project Access rules.

## Two independent permissions

**VM access** decides which Project / Chat can operate a VM. In selected-project
mode, membership is exact: selecting a parent does not select its children.
Selecting no projects grants none. Disabling model access blocks model use; an
explicit human guest console remains available.

**Project Access** decides which other projects a Project / Chat may read.
These grants are direct and read-only. Sharing C with B does not share C with
B's children, expose C's own grants, or allow C's chat to operate B's VM.

VM access controls the execution origin, not the list of source projects. A
child allowed to use a VM still receives its parent files read-only even if
the parent's chat cannot operate that VM.

## One file view per Project / Chat in each VM

| Source | Access in that project's view |
| --- | --- |
| The project's own canonical files | Read/write in live mode; read-only in read-only mode |
| Its direct parent and every earlier ancestor | Read-only |
| Its direct Project Access sources | Read-only |
| Workspace References | Read-only |
| Other projects, siblings, and descendants | Hidden unless separately granted |

Each project has its own sibling `Files/Project-<ID>` directory on the host.
The parent/child relationship does not move these directories into each other.

Linux guest paths are stable:

- Own files: `/workspace/Files/Project-<ID>`.
- References: `/workspace/Files/References`.
- A direct Project Access source: `/workspace/Files/Project-<source-ID>`.
- Ancestors retain the existing nested view: the parent appears inside the
  child's project root, its parent inside that directory, and so on. For
  example, child C sees A through B at
  `/workspace/Files/Project-CCCC/Project-BBBB/Project-AAAA`.
- A Project Access source which is already an ancestor uses that ancestor
  view. It does not acquire another writable alias.

Every model command and project-files terminal must use the same shared plan.
A supported Linux Guest console opens the guest's home and mounts workspace
References read-only at `/workspace/Files/References`. It does not automatically
mount any project's files. This human console view uses the separate
`build_references_policy` plan; it is independent of VM Project membership,
model enable/disable and the project's live, read-only or copy mode. It also
works in a workspace with no projects. Planning never inventories or copies
the directory's contents.

Mount access and Linux privileges are separate. OpenWrt live/read-only project
commands run as the unprivileged `harnessy` user; its human Guest console runs
as root. Lima uses its normal guest user, which can use sudo. Independent-copy
guests retain their existing administration privileges. Project views are not
a security boundary against a guest administrator. Mounting References does
not grant or remove root access.

Build directories, virtual environments and caches belong to the selected VM
and project. They do not move into another VM or project when access changes.

## File modes and provider capabilities

**Live:** reads and writes use canonical host files on demand. There is no
whole-project deployment before opening a shell. Read-only inputs must remain
read-only through every exposed route.

**Read-only:** the same live view, with the project's own files read-only too.

**Independent copy:** files are deployed to the guest disk. The UI and model
must identify these as copies, not live mounts. Refresh and artifact collection
are explicit operations. The transport's size and format limits still apply.
Changing permission cannot recall an independent copy or data already read.

A provider must declare its transport, supported modes, project isolation,
read-only enforcement and runtime reconciliation support. The separate
`guest_references` capability and verified `references` runtime receipt are
required before a Guest console can claim that its References mount is ready.
The console's status must not be mixed into the Project list. Unsupported providers
must not report a successful live mount. Windows currently uses independent
copies; live Windows mounting requires its own verified integration.
Its current copy integration deploys the owned project only. If References
contains files, or the project needs ancestor or Project Access inputs, command
execution reports that unsupported scope before deployment. The guest console
remains available without live References. It must not silently pretend those
read-only inputs exist.

OpenWrt live sharing uses a separate scoped SSHFS/SFTP connection for each
source, over the existing VM SSH transport. No host SSH server or listening
file-sharing port is needed. The host serves regular files and directories on
demand and enforces read-only inputs. Symlinks, multiply linked files and special
files are rejected; keep dependency trees requiring those entries on the guest
disk. Compatible opkg-based guests install matching FUSE/SSHFS packages
automatically. Their Guest console uses a dedicated read-only SFTP capability,
including in independent-copy mode; guest root cannot write through that
capability. The APK-based OpenWrt image remains copy-only and its plain Guest
console reports that live References are unavailable.

Lima Guest consoles use a dedicated host read-only export of the canonical
Files parent, exposing only its References child in the console's namespace.
This allows a replaced References directory to be revalidated without retaining
a stale export of its old inode. An existing running VM without this backing
requires one explicit Stop/Start; it remains pending until then. No automatic
stop, reset or rebuild is allowed. The read-only channel does not remove the
guest administrator's ability to reach other existing Lima exports.

## Updating running VMs

Saving VM access, changing Project Access, changing a parent, or archiving or
removing a source invalidates the affected plans. Reconciliation runs after the
metadata transaction, independently of the UI request, and uses fresh saved
configuration. It must not start a stopped VM just because a checkbox changed.

Background reconciliation owns its task context. It must not inherit a model
request, browser request, or lifecycle progress callback. Lifecycle progress
belongs to one operation ID and expires when that operation finishes; a late
file-sharing update must never put a completed Start back into progress or
overwrite a newer operation.

| Change | Views to refresh |
| --- | --- |
| VM project selection or model enable/disable | Affected project views in that VM |
| Add/remove a direct Project Access grant | Its recipient's views in running VMs |
| Reparent a project | That project and its entire descendant subtree |
| Archive/remove a project | Its views and every remaining consumer |
| Replace a project root or References directory | Every view using the replaced source |
| Restart HarnessyXO or a VM | Rebuild and verify required views from current policy |

Guest console References has its own tracked view and source identity. Editing
an unrelated project's access or hierarchy must not retire its connection.
Replacing References invalidates this view as well as every project view using
that source. An active console can leave retirement pending; a new console
must not enter the stale namespace. Close affected consoles, then retry. The
preparation lease must remain held until the terminal session has acquired its
own lease, with only the same owner's preparation exempted during reconciliation.
Acquire this lease under the reconciliation lock after any ongoing mount work
finishes, so opening a console immediately after Start queues instead of racing
the background first mount. Cancelling that wait must not create a terminal.

Source use is tracked per consuming view. Removing A's VM permission must not
detach A's read-only files from an allowed child B. Removing B's grant to C
must not detach C from another project which still has its own valid grant.

New model calls are denied immediately after their VM permission is revoked.
A call must not enter an outdated view after a source grant or hierarchy change.
Changes reconcile without restarting the VM or interrupting unrelated projects.

An in-use view is reported as **Unmount pending**. The user can finish or stop
that project's commands and close its project terminal, then retry. A supported
stop-and-unmount action must stop only the affected project's tracked work.
Unmounting or lazy-detaching alone cannot revoke open file descriptors, current
working directories, memory mappings or data a process already read.

## Failure and data preservation

The UI and diagnostics distinguish requested policy from verified runtime
state: preparing, mounted, pending, stopped, unsupported or failed. References
status is separate from project status: a References failure must not block
an otherwise verified project, and a broken project must not block the human
References console. A saved
checkbox is not proof that a mount operation succeeded. Failures retain a
useful cause and can be retried.

Permission changes never delete canonical files, References, guest build
directories, virtual environments, caches or independent project copies.
Mount cleanup removes only controller-owned views and transport connections.
Symlink redirects, replaced source identities and stale runtime records must
be revalidated before mounting, serving, collecting or retiring a view.
If the workspace disappears or its database generation changes, reconciliation
stops. It must not initialize a replacement workspace in an empty mount point.

Live sharing is a filesystem transport, not a promise that an already-open file
or memory mapping instantly observes an edit from another machine. Reopening a
file refreshes its contents. Providers must preserve normal executable and
file-backed memory-mapping support, and state any transport limitations.

No provider may export the host home, workspace metadata, credentials, host
sockets or unrelated projects as a shortcut to implementing project sharing.
The existing Lima backing export is hidden from scoped project commands; it
does not provide protection against a human guest administrator. Providers
which cannot enforce the requested view must fail with a clear capability
error and leave the source files untouched.
