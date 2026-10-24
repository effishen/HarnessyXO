"""Owned SSHFS passive channels for exact, on-demand OpenWrt file exports.

Each source has its own SFTP capability and guest mount. There is no host
listener, workspace export, archive, source inventory or write-back collector.
Only controller-created mount points and connections are retired.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shlex
import re
import stat
import time
import weakref

from .project_sftp import serve_sftp

MAX_VIEWS = 64
MAX_SOURCES = 64


class LiveMountBusyError(RuntimeError):
    """The guest retained an open reference to an owned source mount."""

_REGISTRY: dict[tuple[str, str, int], tuple[weakref.ReferenceType, 'OpenWrtLiveMounts']] = {}


def live_mounts(owner):
    """Transport ownership survives provider-cache eviction on settings save."""
    loop = asyncio.get_running_loop()
    key = (str(owner.workspace_root), owner.config.id, id(loop))
    current = _REGISTRY.get(key)
    if current is None or current[0]() is not loop:
        current = (weakref.ref(loop), OpenWrtLiveMounts(owner))
        _REGISTRY[key] = current
    current[1].owner = owner
    # Closed loops cannot serve a capability. Their stale guest mount points
    # are verified/unmounted by _mount before a fresh connection is attached.
    for old_key, (reference, _) in list(_REGISTRY.items()):
        previous = reference()
        if old_key != key and (previous is None or previous.is_closed()):
            _REGISTRY.pop(old_key, None)
    return current[1]


@dataclass
class Export:
    path: str
    process: asyncio.subprocess.Process
    revoked: asyncio.Event
    serving: asyncio.Task
    draining: asyncio.Task
    errors: bytearray = field(default_factory=bytearray)
    closing: bool = False


@dataclass
class View:
    key: str
    project_id: str
    signature: str
    projection: dict
    exports: list[Export] = field(default_factory=list)


class OpenWrtLiveMounts:
    def __init__(self, owner):
        self.owner = owner
        self.views: dict[str, View] = {}
        self.lock = asyncio.Lock()
        self.packages_verified = False
        self._stale_paths = None

    @staticmethod
    def signature(projection):
        sources = []
        expected = {str(item['path']): item for item in projection['policy'].get('source_identities', ())}
        if not expected:
            raise RuntimeError('Project source identities must be verified before mounting.')
        for row in projection['mounts']:
            host = Path(row['host'])
            info = host.lstat()
            planned = expected.get(str(host))
            if (not stat.S_ISDIR(info.st_mode) or not planned or
                    (info.st_dev, info.st_ino) != (planned['device'], planned['inode'])):
                raise RuntimeError('A project source was replaced or redirected; request its current file plan.')
            if any(parent.is_symlink() for parent in host.parents):
                raise RuntimeError('A project source parent was redirected; source access was refused.')
            sources.append((str(row['host']), row['guest'], row['writable'],
                            tuple(row['excluded']), info.st_dev, info.st_ino))
        return hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()

    def verified(self, projection):
        """Commands consume a reconciled view; only reconciliation mutates it."""
        view = self.views.get(projection['key'])
        if (view is None or view.signature != self.signature(projection) or
                view.projection['policy'].get('policy_revision') != projection['policy'].get('policy_revision') or
                any(item.serving.done() or item.process.returncode is not None for item in view.exports)):
            from .file_views import FileViewUnavailableError
            raise FileViewUnavailableError('The live project view changed or disconnected; retry after its file access is prepared.', 'FILE_VIEW_POLICY_CHANGED')
        return view

    async def prepare(self):
        if self.owner._basic_copy:
            raise RuntimeError('This OpenWrt release supports independent copies; verified SSHFS integration is unavailable.')
        if self.packages_verified:
            return
        await self.owner._emit('provisioning_packages', 'Installing matching FUSE and SSHFS support for live project files…')
        await self.owner._install_packages(('kmod-fuse', 'sshfs'))
        await self.owner._checked('modprobe fuse && test -c /dev/fuse && command -v sshfs >/dev/null && command -v fusermount3 >/dev/null')
        self.packages_verified = True

    async def ensure(self, projection, *, project_id='') -> View:
        async with self.lock:
            signature = self.signature(projection)
            old = self.views.get(projection['key'])
            if old and old.signature == signature and all(not item.serving.done() and item.process.returncode is None for item in old.exports):
                # Only the origin/source policy is mutable. Writer ownership
                # comes from the scheduler's current exact-project lease.
                old.projection['policy'] = dict(projection['policy'])
                return old
            if old:
                await self._retire(old)
            if len(self.views) >= MAX_VIEWS or len(projection['mounts']) > MAX_SOURCES:
                raise RuntimeError('Too many active OpenWrt project sources; retire unused project views before retrying.')
            await self.prepare()
            view = View(projection['key'], str(project_id), signature, projection)
            try:
                await self.owner._checked('set -eu\n'
                    '[ ! -L /opt ] && [ ! -L /opt/harnessy-private ]\n'
                    'mkdir -p /opt/harnessy-private/live\n'
                    '[ ! -L /opt/harnessy-private/live ]\n'
                    'chmod 700 /opt/harnessy-private /opt/harnessy-private/live\n'
                    + 'mkdir -m 700 -p ' + shlex.quote(projection['remote']))
                for index, row in enumerate(projection['mounts']):
                    view.exports.append(await self._mount(view, index, row))
                if self.signature(projection) != signature:
                    raise RuntimeError('Project sources changed while mounting; request their current file plan.')
                self.views[view.key] = view
                if self._stale_paths is not None:
                    self._stale_paths.pop(view.key, None)
                return view
            except BaseException:
                await self._retire(view, force=True)
                raise

    async def _mount(self, view: View, index: int, row: dict) -> Export:
        path = view.projection['remote'] + '/' + str(index)
        # A previous app process may have left a disconnected FUSE mount. A
        # normal unmount must succeed; a busy view is never silently detached.
        await self.owner._checked('set -eu\n'
            + 'if grep -Fq ' + shlex.quote(' ' + path + ' fuse.sshfs ') + ' /proc/mounts; then fusermount3 -u ' + shlex.quote(path) + '; fi\n'
            + '[ ! -L ' + shlex.quote(path) + ' ]\nmkdir -m 700 -p ' + shlex.quote(path))
        options = ['passive', 'allow_other', 'default_permissions', 'uid=1000', 'gid=1000',
                   'nosuid', 'nodev', 'cache=no', 'dir_cache=no', 'entry_timeout=0',
                   'attr_timeout=0', 'negative_timeout=0', 'no_readahead', 'sshfs_sync', 'disable_hardlink']
        if not row['writable']:
            options.append('ro')
        command = 'exec sshfs :/ ' + shlex.quote(path) + ' -f -o ' + shlex.quote(','.join(options))
        # The persistent file stream must not share a command control socket.
        argv, env = self.owner.controller.command(command, reuse_connection=False)
        process = await asyncio.create_subprocess_exec(*argv, env=env, cwd=self.owner.environment_root,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        revoked = asyncio.Event()
        errors = bytearray()
        async def drain():
            while chunk := await process.stderr.read(4096):
                errors.extend(chunk)
                if len(errors) > 8192:
                    del errors[:-8192]
        # Every write uses the exact origin's current scheduler lease; no
        # caller-provided mutation owner is retained by the shared channel.
        serving = asyncio.create_task(serve_sftp(process.stdout, process.stdin, row['host'],
            writable=bool(row['writable']), excluded=tuple(row['excluded']), revoked=revoked,
            mutation=(lambda: self.owner._host_writer(view.projection)) if row['writable'] else None))
        item = Export(path, process, revoked, serving, asyncio.create_task(drain()), errors)
        def channel_finished(task):
            if item.closing or item.revoked.is_set():
                return
            # A failed channel must invalidate the ready badge even while no
            # model tool is running. Never log SFTP payload or guest prose.
            from .file_views import FILE_VIEWS
            from harnessy.diagnostics import log_event
            log_event('runtime', 'file_view_transport_failed', environment_id=self.owner.config.id,
                      project_id=view.project_id, error_code='FILE_VIEW_TRANSPORT_FAILED')
            FILE_VIEWS.request(self.owner.workspace_root, reason='file_view_transport_failed',
                               environment_id=self.owner.config.id)
        serving.add_done_callback(channel_finished)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if serving.done() or process.returncode is not None:
                    if serving.done() and not serving.cancelled():
                        error = serving.exception()
                        if error:
                            raise RuntimeError('The scoped project file server failed.') from error
                    raise RuntimeError('SSHFS did not mount the project source: ' + errors.decode(errors='replace')[-1500:])
                rc, _, _ = await self.owner._raw('grep -Fq ' + shlex.quote(' ' + path + ' fuse.sshfs ') + ' /proc/mounts', timeout=5)
                if rc == 0:
                    return item
                await asyncio.sleep(.1)
            raise TimeoutError('SSHFS project mounting timed out; source files were preserved.')
        except BaseException:
            await self._close_export(item, force=True)
            raise

    async def _close_export(self, item: Export, *, force=False):
        item.closing = True
        if not force:
            # Existing descriptors and namespace bind mounts must be retired
            # by the caller before a source capability can be withdrawn.
            try:
                await self.owner._checked('if grep -Fq ' + shlex.quote(' ' + item.path + ' fuse.sshfs ')
                    + ' /proc/mounts; then fusermount3 -u ' + shlex.quote(item.path) + '; fi', timeout=10)
            except BaseException as error:
                item.closing = False
                if any(text in str(error).lower() for text in ('device or resource busy', 'target is busy', 'mountpoint is busy')):
                    raise LiveMountBusyError('This project mount is still in use inside the guest. Close its files and project terminals, then retry unmounting.') from error
                raise
        item.revoked.set()
        if item.process.returncode is None:
            item.process.terminate()
        try:
            await asyncio.wait_for(item.process.wait(), 5)
        except asyncio.TimeoutError:
            item.process.kill()
            await item.process.wait()
        if not item.serving.done():
            item.serving.cancel()
        await asyncio.gather(item.serving, item.draining, return_exceptions=True)
        if force:
            # Used only after an owned launch fails, or after the guest stops.
            # Never remove a source directory or canonical file.
            try:
                await self.owner._raw('fusermount3 -u ' + shlex.quote(item.path), timeout=5)
            except (OSError, RuntimeError, TimeoutError):
                pass

    async def _retire(self, view: View, *, force=False):
        for item in reversed(view.exports):
            await self._close_export(item, force=force)
        self.views.pop(view.key, None)

    async def retire_project(self, project_id, *, force=False):
        async with self.lock:
            for view in list(self.views.values()):
                if view.project_id == project_id:
                    await self._retire(view, force=force)

    async def retire_stale(self, folder):
        """Retire only exact owned paths after an app-process restart.

        No source data is removed. Busy old descriptors cause a visible error;
        they are never hidden with a lazy detach.
        """
        if not re.fullmatch(r'Project-[A-Za-z0-9]{4}', str(folder)):
            raise ValueError('Invalid stale project view identity.')
        root = self.owner.files_root / folder
        key = hashlib.sha256(str(root).encode()).hexdigest()[:24]
        prefix = '/opt/harnessy-private/live/' + key + '/'
        async with self.lock:
            if key in self.views:
                return
            if self._stale_paths is None:
                rc, output, error = await self.owner._raw("awk '$3 == \"fuse.sshfs\" { print $2 }' /proc/mounts", timeout=10)
                if rc:
                    raise RuntimeError('Cannot inspect stale project mounts before withdrawing source access.')
                found = {}
                for raw in output.splitlines():
                    path = raw.decode('ascii', errors='replace')
                    match = re.fullmatch(r'/opt/harnessy-private/live/([a-f0-9]{24})/([0-9]{1,3})', path)
                    if match:
                        found.setdefault(match[1], []).append(path)
                if sum(map(len, found.values())) > MAX_VIEWS * MAX_SOURCES:
                    raise RuntimeError('Unexpected number of stale owned project mounts; inspect the guest console.')
                self._stale_paths = found
            paths = self._stale_paths.get(key, ())
            for path in reversed(paths):
                await self.owner._checked('if grep -Fq ' + shlex.quote(' ' + path + ' fuse.sshfs ')
                    + ' /proc/mounts; then fusermount3 -u ' + shlex.quote(path) + '; fi', timeout=10)
            self._stale_paths.pop(key, None)

    async def close(self, *, force=False):
        async with self.lock:
            for view in list(self.views.values()):
                await self._retire(view, force=force)
            self.packages_verified = False
            self._stale_paths = None


async def close_workspace_live_mounts(root):
    """Drain owned source channels when an admitted workspace is unloaded."""
    loop = asyncio.get_running_loop()
    for key, (reference, manager) in list(_REGISTRY.items()):
        if key[0] == str(Path(root).resolve()) and reference() is loop:
            await manager.close(force=True)
            _REGISTRY.pop(key, None)


async def close_environment_live_mounts(root, environment_id):
    """Close only one removed VM's owned source channels."""
    loop = asyncio.get_running_loop()
    for key, (reference, manager) in list(_REGISTRY.items()):
        if key[:2] == (str(Path(root).resolve()), str(environment_id)) and reference() is loop:
            await manager.close(force=True)
            _REGISTRY.pop(key, None)
