"""Process-owned reconciliation of authoritative project file-view plans."""
from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
import uuid
from contextvars import Context
from pathlib import Path
from typing import Any

from .base import environment_root, _validate_registry_path, EnvironmentModelAccessError, FileViewUnavailableError


async def finish_file_view_work(function, *args):
    """Drain controller-owned filesystem/SQLite reads before cancellation."""
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        raise


class FileViewRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._loops = {}
        self._states = {}
        self._generations = {}
        self._tasks = {}
        self._async_locks = {}
        self._workspaces = {}
        self._logged = {}
        self._started_revisions = {}
        self._closed = set()
        self._closed_environments = set()

    def forget_environment(self, root, *, environment_id):
        """Synchronous tombstone before an owned VM directory is removed."""
        key = self._key(root, environment_id)
        with self._lock:
            self._closed_environments.add(key)
            tasks = [task for task_key, task in self._tasks.items() if task_key[:2] == key and not task.done()]
        for task in tasks:
            loop = task.get_loop()
            if not loop.is_closed():
                loop.call_soon_threadsafe(task.cancel)

    async def close_environment(self, root, *, environment_id):
        key = self._key(root, environment_id)
        tasks = [task for task_key, task in self._tasks.items() if task_key[:2] == key and not task.done()]
        self.forget_environment(root, environment_id=environment_id)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        module = sys.modules.get('harnessy.environment.openwrt_environment')
        closer = getattr(module, 'close_environment_live_mounts', None)
        if closer is not None:
            await closer(Path(root), environment_id)
        with self._lock:
            self._states.pop(key, None)

    def _is_closed(self, key):
        return key[0] in self._closed or key in self._closed_environments

    def _log_result(self, key, state, started):
        references = state.get('references') or {}
        signature = (state.get('state'), state.get('requested_revision'),
                     tuple(state.get('pending_project_ids') or ()), state.get('error_code'),
                     references.get('state'), references.get('policy_revision'), references.get('error_code'))
        if self._logged.get(key) == signature:
            return
        self._logged[key] = signature
        from harnessy.diagnostics import log_event
        outcome = ('failed' if state.get('state') == 'error' else 'unsupported' if state.get('state') == 'unsupported'
                   else 'pending' if state.get('state') == 'pending' or state.get('pending_project_ids')
                   or references.get('state') == 'pending' else 'applied')
        log_event('runtime', 'file_view_reconciliation_' + outcome, environment_id=key[1],
                  state=state.get('state'), error_code=state.get('error_code') or '',
                  requested_revision=state.get('requested_revision') or '',
                  applied_revision=state.get('applied_revision') or '',
                  project_count=len(state.get('projects') or ()), pending_count=len(state.get('pending_project_ids') or ()),
                  references_state=references.get('state') or '', references_error_code=references.get('error_code') or '',
                  duration_seconds=max(0, time.monotonic() - started))

    def register_workspace(self, workspace) -> None:
        with self._lock:
            root = str(Path(workspace.root).resolve())
            self._closed.discard(root)
            self._workspaces[root] = workspace
        self.observe(workspace.root)

    def cached_workspace(self, root):
        from harnessy.core.workspace_access import workspace_generation
        key = str(Path(root).resolve())
        with self._lock:
            workspace = self._workspaces.get(key)
        if workspace is not None and workspace._workspace_generation == workspace_generation(Path(key)):
            return workspace
        return None

    async def workspace(self, root):
        workspace = self.cached_workspace(root)
        if workspace is None:
            raise RuntimeError('Open this workspace again to verify its database and file policy before using VM project files.')
        return workspace

    async def acquire_terminal_activity(self, root, *, environment_id, project_id,
                                         owner_id: str = '', label: str = 'Opening terminal'):
        """Queue behind reconciliation, then pin its verified view for a PTY.

        The same VM lock covers both the wait and synchronous lease acquisition.
        A background first mount therefore cannot race a new terminal into an
        immediate reservation failure. Cancellation while waiting owns no lease.
        """
        from .activity import acquire_activity
        key = self._key(root, environment_id)
        lock_key = (*key, id(asyncio.get_running_loop()))
        async with self._async_locks.setdefault(lock_key, asyncio.Lock()):
            if self._is_closed(key) or self.cached_workspace(root) is None:
                raise FileViewUnavailableError('Reopen this workspace before opening a VM terminal.', 'FILE_VIEW_FAILED')
            return acquire_activity(root, label, environment_id=environment_id,
                                    project_id=project_id, owner_id=owner_id)

    async def close(self, root) -> None:
        """Drain runtime workers before workspace unregister/removal."""
        root = str(Path(root).resolve())
        with self._lock:
            self._closed.add(root)
            tasks = [task for key, task in self._tasks.items() if key[0] == root and not task.done()]
            self._workspaces.pop(root, None)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        # The module is already loaded whenever it owns an SFTP transport.
        # Closing a missing/legacy workspace must not initialize a provider.
        module = sys.modules.get('harnessy.environment.openwrt_environment')
        closer = getattr(module, 'close_workspace_live_mounts', None)
        if closer is not None:
            await closer(Path(root))
        with self._lock:
            self._loops.pop(root, None)
            for mapping in (self._tasks, self._async_locks, self._states, self._generations):
                for key in [key for key in mapping if key[0] == root]:
                    mapping.pop(key, None)

    async def shutdown(self) -> None:
        for root in set(self._loops) | {key[0] for key in self._tasks}:
            await self.close(root)

    def observe(self, root) -> None:
        if str(Path(root).resolve()) in self._closed:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        with self._lock:
            self._loops[str(Path(root).resolve())] = loop

    @staticmethod
    def _key(root, environment_id):
        return str(Path(root).resolve()), str(environment_id)

    def _persist(self, key, state):
        root, environment_id = key
        owned = environment_root(root, environment_id)
        path = owned / 'state' / 'file-views.json'
        for candidate in (owned, path.parent, path):
            _validate_registry_path(candidate, root)
        if not (owned / 'environment.json').is_file():
            return  # Never resurrect a removed VM definition.
        path.parent.mkdir(parents=True, exist_ok=True)
        safe = {name: state.get(name) for name in ('schema', 'environment_id', 'state', 'requested_revision',
                'applied_revision', 'updated_at', 'error_code', 'pending_project_ids', 'capabilities', 'busy', 'stage')}
        safe['projects'] = [{name: row.get(name) for name in ('project_id', 'folder', 'state', 'policy_revision', 'error_code')}
                            for row in state.get('projects', ())]
        safe['references'] = {name: (state.get('references') or {}).get(name)
                              for name in ('state', 'policy_revision', 'error_code')}
        temporary = path.with_name('.file-views-' + uuid.uuid4().hex + '.tmp')
        try:
            with temporary.open('x', encoding='utf-8') as stream:
                json.dump(safe, stream, sort_keys=True)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def _load(self, key):
        path = environment_root(key[0], key[1]) / 'state' / 'file-views.json'
        _validate_registry_path(path, key[0])
        try:
            if path.stat().st_size > 1024 * 1024:
                raise ValueError('Runtime file-view status is oversized.')
            value = json.loads(path.read_text())
            if not isinstance(value, dict) or value.get('environment_id') != key[1]:
                raise ValueError('Invalid runtime file-view status identity.')
            from harnessy.core.project_access import canonical_project_id
            from harnessy.core.outputs import CHAT_OUTPUT_DIR_RE
            rows = value.get('projects', [])
            if not isinstance(rows, list) or len(rows) > 10000:
                raise ValueError('Invalid runtime project file-view rows.')
            for row in rows:
                if (not isinstance(row, dict) or not canonical_project_id(row.get('project_id'))
                        or not isinstance(row.get('folder'), str) or not CHAT_OUTPUT_DIR_RE.fullmatch(row['folder'])):
                    raise ValueError('Invalid runtime project file-view identity.')
            return value
        except FileNotFoundError:
            return {}

    def _publish(self, key, **values):
        with self._lock:
            if self._is_closed(key):
                return {'state': 'closed', 'environment_id': key[1], 'projects': [], 'pending_project_ids': []}
            state = {**self._states.get(key, {}), **values, 'schema': 1, 'environment_id': key[1], 'updated_at': time.time()}
            self._states[key] = state
            try:
                self._persist(key, state)
            except Exception as exc:
                state.update(error_code='FILE_VIEW_STATUS_WRITE_FAILED', error=type(exc).__name__)
                from harnessy.diagnostics import log_event
                log_event('runtime', 'file_view_status_write_failed', environment_id=key[1], error=type(exc).__name__)
        return dict(state)

    def request(self, root, *, reason: str, project_ids=None, environment_id=None) -> None:
        from .manager import EnvironmentManager
        self.observe(root)
        if str(Path(root).resolve()) in self._closed:
            return
        try:
            configs = EnvironmentManager(root).list()
        except Exception as exc:
            # The metadata transaction has already committed. A broken VM
            # registry must not report that creating/editing a chat failed.
            from harnessy.diagnostics import log_event
            log_event('runtime', 'file_view_reconciliation_failed',
                      error_code='FILE_VIEW_REGISTRY_INVALID', error_type=type(exc).__name__)
            return
        for config in configs:
            if environment_id is not None and config.id != environment_id:
                continue
            key = self._key(root, config.id)
            if self._is_closed(key):
                continue
            with self._lock:
                if key not in self._states:
                    try:
                        self._states[key] = self._load(key)
                    except Exception:
                        self._states[key] = {}
                self._generations[key] = self._generations.get(key, 0) + 1
                self._publish(key, state='pending', reason=str(reason)[:80], error='', error_code='',
                              busy=False, stage='queued', requested_revision='pending-' + uuid.uuid4().hex)
            self._schedule(key)
            from harnessy.diagnostics import log_event
            log_event('runtime', 'file_view_reconciliation_requested', environment_id=config.id, reason=str(reason)[:80])

    def _schedule(self, key):
        with self._lock:
            loop = self._loops.get(key[0])
        if loop is None or loop.is_closed():
            return
        def launch():
            if self._is_closed(key):
                return
            task_key = (*key, id(loop))
            task = self._tasks.get(task_key)
            if task is None or task.done():
                # This service owns its workspace/environment identity and
                # obtains writer authority explicitly. A request's lifecycle
                # progress callback, model selection or UI context must not
                # survive in its independent background worker.
                self._tasks[task_key] = loop.create_task(self._worker(key),
                    name='harnessy-file-views-' + key[1], context=Context())
        loop.call_soon_threadsafe(launch, context=Context())

    def activity_released(self, root, *, environment_id=None):
        workspace_root = str(Path(root).resolve())
        with self._lock:
            keys = [key for key, state in self._states.items() if key[0] == workspace_root
                    and (environment_id is None or key[1] == environment_id)
                    and (state.get('state') == 'pending' or state.get('pending_project_ids')
                         or (state.get('references') or {}).get('state') == 'pending')]
        for key in keys:
            self._schedule(key)

    async def _worker(self, key):
        while True:
            before = self._generations.get(key, 0)
            result = await self.reconcile(key[0], environment_id=key[1])
            if self._generations.get(key, 0) != before:
                continue
            # Activity release and VM lifecycle completion schedule the next
            # attempt. Never poll an idle/broken controller forever while a
            # terminal stays open or first-boot setup requires user action.
            return

    def status(self, root, *, environment_id) -> dict[str, Any]:
        self.observe(root)
        key = self._key(root, environment_id)
        if self._is_closed(key):
            return {'state': 'closed', 'projects': [], 'pending_project_ids': []}
        with self._lock:
            if key not in self._states:
                self._states[key] = self._load(key)
                # Persisted status describes a previous controller lifetime.
                # Reverify running guests; never trust a saved Mounted badge.
                self.request(root, reason='runtime_observer_started', environment_id=environment_id)
            state = dict(self._states.get(key, {}))
        if state.get('state') == 'pending' and state.get('stage') == 'queued':
            self._schedule(key)
        return state

    async def reconcile(self, root, *, environment_id, owner_id: str = '') -> dict[str, Any]:
        from .manager import EnvironmentManager
        from harnessy.core.project_mounts import build_environment_plan
        self.observe(root)
        key = self._key(root, environment_id)
        if self._is_closed(key):
            return {'state': 'closed', 'projects': [], 'pending_project_ids': []}
        lock_key = (*key, id(asyncio.get_running_loop()))
        async with self._async_locks.setdefault(lock_key, asyncio.Lock()):
            started = time.monotonic()
            generation = self._generations.get(key, 0)
            try:
                self._publish(key, state='preparing', busy=True, stage='planning', detail='Checking the saved project file policy…')
                manager = EnvironmentManager(root, environment_id=environment_id)
                config = manager.config
                if config is None:
                    return {'state': 'removed', 'projects': [], 'pending_project_ids': []}
                workspace = await self.workspace(root)
                plan = await finish_file_view_work(build_environment_plan, workspace, config)
                if self._is_closed(key) or manager.config is None:
                    return {'state': 'removed', 'projects': [], 'pending_project_ids': []}
                if self._started_revisions.get(key) != plan['revision']:
                    self._started_revisions[key] = plan['revision']
                    from harnessy.diagnostics import log_event
                    log_event('runtime', 'file_view_reconciliation_started', environment_id=environment_id,
                              requested_revision=plan['revision'], project_count=len(plan['projects']))
                plan['_owner_id'] = str(owner_id or '')
                previous = self._states.get(key, {})
                # Retain deleted origin IDs until their old namespaces retire.
                known = {row['project_id']: row for row in plan['known_projects']}
                claimed_folders = {row['folder'] for row in known.values()}
                for row in previous.get('projects', ()):
                    if (row.get('project_id') and row['project_id'] not in known
                            and row.get('folder') not in claimed_folders):
                        known[row['project_id']] = {'project_id': row['project_id'], 'folder': row.get('folder', '')}
                        claimed_folders.add(row.get('folder'))
                plan['known_projects'] = list(known.values())
                provider = manager.provider(config)
                capabilities = provider.file_view_capabilities()
                references_revision = (plan.get('references_policy') or {}).get('policy_revision', '')
                def references_row(state, detail='', code=''):
                    return {'state': state, 'policy_revision': references_revision,
                            'detail': detail, 'error_code': code}
                unsupported_references = references_row('unsupported',
                    'Live References are unavailable for this VM provider.', 'FILE_VIEW_UNSUPPORTED')
                from .operations import ENVIRONMENT_OPERATIONS
                if ENVIRONMENT_OPERATIONS.is_busy(root, environment_id=environment_id):
                    return self._publish(key, state='pending', detail='Waiting for this VM operation to finish.',
                                         busy=False, stage='waiting_for_vm_operation',
                                         projects=[{'project_id': row['project_id'], 'folder': row['folder'], 'state': 'pending'} for row in plan['projects']],
                                         references=references_row('pending', 'Waiting for this VM operation to finish.')
                                         if capabilities.get('guest_references') else unsupported_references,
                                         pending_project_ids=[row['project_id'] for row in plan['projects']], capabilities=capabilities)
                status = await provider.status()
                if not status.running:
                    result = {'state': 'stopped', 'revision': '', 'projects': [
                        {'project_id': row['project_id'], 'folder': row['folder'], 'state': 'stopped'} for row in plan['projects']],
                        'pending_project_ids': [], 'detail': 'Views will be prepared when this VM is used.',
                        'references': references_row('stopped') if capabilities.get('guest_references') else unsupported_references}
                elif not status.ready:
                    result = {'state': 'pending', 'projects': [
                        {'project_id': row['project_id'], 'folder': row['folder'], 'state': 'pending', 'detail': 'Waiting for this VM to become Ready.'} for row in plan['projects']],
                        'pending_project_ids': [row['project_id'] for row in plan['projects']],
                        'stage': 'waiting_for_ready', 'detail': 'Waiting for this VM to become Ready.',
                        'references': references_row('pending', 'Waiting for this VM to become Ready.')
                        if capabilities.get('guest_references') else unsupported_references}
                elif (config.files_mode not in capabilities.get('supported_modes', ())
                      or (config.files_mode != 'copy' and not all(capabilities.get(name) for name in
                          ('runtime_mounts', 'project_isolation', 'readonly_inputs', 'reconcile', 'composite')))):
                    result = {'state': 'unsupported', 'error_code': 'FILE_VIEW_UNSUPPORTED',
                        'detail': 'This VM provider cannot enforce the requested file mode and project policy.',
                        'projects': [{'project_id': row['project_id'], 'folder': row['folder'], 'state': 'unsupported',
                                      'error_code': 'FILE_VIEW_UNSUPPORTED'} for row in plan['projects']],
                        'pending_project_ids': [], 'references': references_row('error',
                            'This VM cannot verify its file-view integration.', 'FILE_VIEW_UNSUPPORTED')
                        if capabilities.get('guest_references') else unsupported_references}
                else:
                    self._publish(key, state='preparing', busy=True, stage='reconciling', capabilities=capabilities,
                                  detail='Applying and verifying project file views…')
                    result = await provider.reconcile_file_views(plan)
                if not capabilities.get('guest_references'):
                    result['references'] = unsupported_references
                elif plan.get('references_error') and (result.get('references') or {}).get('state') not in {'pending', 'stopped'}:
                    result['references'] = references_row('error',
                        plan['references_error'].get('detail', 'References could not be safely verified.'), 'FILE_VIEW_SOURCE_INVALID')
                else:
                    references = result.get('references')
                    if not isinstance(references, dict):
                        result['references'] = references_row('error',
                            'The VM did not return a verified References state.', 'FILE_VIEW_FAILED')
                    elif references.get('state') == 'ready' and references.get('policy_revision') != references_revision:
                        result['references'] = references_row('pending',
                            'References changed while its mount was being verified.', 'FILE_VIEW_POLICY_CHANGED')
                policies = {row['project_id']: row['policy']['policy_revision'] for row in plan['projects']}
                result['projects'] = [{**row, 'policy_revision': policies.get(row.get('project_id'), '')}
                                      for row in result.get('projects', ())]
                latest_config = EnvironmentManager(root, environment_id=environment_id).config
                if latest_config is not None:
                    latest_plan = await finish_file_view_work(build_environment_plan, workspace, latest_config)
                    if latest_plan['revision'] != plan['revision']:
                        latest_policies = {row['project_id']: row['policy']['policy_revision'] for row in latest_plan['projects']}
                        changed_ids = {project_id for project_id in {*policies, *latest_policies}
                                       if policies.get(project_id) != latest_policies.get(project_id)}
                        self.request(root, reason='policy_changed_during_reconcile', environment_id=environment_id)
                        result = {**result, 'state': 'pending', 'error_code': 'FILE_VIEW_POLICY_CHANGED',
                                  'pending_project_ids': sorted(changed_ids),
                                  'projects': [{**row, 'state': 'pending' if row.get('project_id') in changed_ids else row.get('state')}
                                               for row in result['projects']]}
                        if (latest_plan.get('references_policy') or {}).get('policy_revision', '') != references_revision:
                            result['references'] = references_row('pending',
                                'References changed during reconciliation.', 'FILE_VIEW_POLICY_CHANGED')
                if generation != self._generations.get(key, 0):
                    return self._publish(key, **{**result, 'state': 'pending', 'busy': False, 'stage': 'queued',
                                         'detail': 'Saved project access changed during reconciliation.'})
                errors = plan.get('errors', [])
                if errors:
                    merged_rows = {row['project_id']: row for row in [*result.get('projects', []), *errors]}
                    result = {**result, 'state': 'error', 'projects': list(merged_rows.values()),
                              'error_code': 'FILE_VIEW_SOURCE_INVALID', 'error': 'Some project sources could not be safely verified.'}
                references = result.get('references') or {}
                if references.get('state') == 'error':
                    result.update(state='error', error_code=references.get('error_code') or 'FILE_VIEW_FAILED')
                elif references.get('state') == 'pending' and result.get('state') not in {'error', 'unsupported'}:
                    result['state'] = 'pending'
                values = {'detail': '', 'error': '', 'error_code': '', **result, 'capabilities': capabilities, 'busy': False,
                          'stage': result.get('stage') or ('in_use' if result.get('pending_project_ids')
                                    or references.get('state') == 'pending' else result.get('state', '')),
                          'requested_revision': plan['revision'],
                          'applied_revision': plan['revision'] if result.get('state') == 'ready' else previous.get('applied_revision', '')}
                published = self._publish(key, **values)
                self._log_result(key, published, started)
                return published
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                published = self._publish(key, state='error', busy=False, stage='failed', error=str(exc)[:1000],
                                          error_code='FILE_VIEW_RECONCILIATION_FAILED', detail='File views could not be verified.',
                                          projects=[], pending_project_ids=[],
                                          references={'state': 'error', 'error_code': 'FILE_VIEW_RECONCILIATION_FAILED'})
                self._log_result(key, published, started)
                return published

    async def ensure_project(self, root, *, environment_id, project_id, owner_id: str = '', human: bool = False):
        from .manager import EnvironmentManager
        from harnessy.core.project_mounts import build_project_policy
        config = EnvironmentManager(root, environment_id=environment_id).config
        if config is None or not config.allows_project(project_id) or (not human and not config.enabled):
            raise EnvironmentModelAccessError('This Project / Chat does not have access to the selected VM file view.')
        state = await self.reconcile(root, environment_id=environment_id, owner_id=owner_id)
        row = next((row for row in state.get('projects', ()) if row.get('project_id') == project_id), None)
        if row is None or row.get('state') != 'ready':
            kind = (row or {}).get('state') or state.get('state')
            code = ('FILE_VIEW_POLICY_CHANGED' if state.get('error_code') == 'FILE_VIEW_POLICY_CHANGED' else
                    'FILE_VIEW_UNSUPPORTED' if kind == 'unsupported' else
                    'FILE_VIEW_PENDING' if kind in {'pending', 'preparing', 'stopped'} else 'FILE_VIEW_FAILED')
            raise FileViewUnavailableError((row or {}).get('detail') or state.get('error') or state.get('detail') or 'Project file view is not ready.', code)
        config = EnvironmentManager(root, environment_id=environment_id).config
        if config is None or not config.allows_project(project_id) or (not human and not config.enabled):
            raise EnvironmentModelAccessError('Project access changed while preparing this VM file view.')
        workspace = await self.workspace(root)
        policy = await finish_file_view_work(build_project_policy, workspace, project_id)
        if row.get('policy_revision') != policy['policy_revision']:
            self.request(root, reason='project_policy_changed_during_prepare', environment_id=environment_id)
            raise FileViewUnavailableError('Project file policy changed while its view was being verified. Retry after reconciliation.', 'FILE_VIEW_POLICY_CHANGED')
        return {**policy, '_human_project_id' if human else '_model_project_id': project_id}

    async def ensure_references(self, root, *, environment_id, owner_id: str = ''):
        """Verify a human console's RO References independently of Project ACLs."""
        from .manager import EnvironmentManager
        from harnessy.core.project_mounts import build_references_policy
        key = self._key(root, environment_id)
        config = EnvironmentManager(root, environment_id=environment_id).config
        if self._is_closed(key) or config is None:
            raise FileViewUnavailableError('This VM or workspace is no longer available.', 'FILE_VIEW_FAILED')
        provider = EnvironmentManager(root, environment_id=environment_id).provider(config)
        if not provider.file_view_capabilities().get('guest_references'):
            raise FileViewUnavailableError('Live References are unavailable for this VM provider.', 'FILE_VIEW_UNSUPPORTED')
        state = await self.reconcile(root, environment_id=environment_id, owner_id=owner_id)
        row = state.get('references') or {}
        if row.get('state') != 'ready':
            kind = row.get('state') or state.get('state')
            code = ('FILE_VIEW_POLICY_CHANGED' if row.get('error_code') == 'FILE_VIEW_POLICY_CHANGED' else
                    'FILE_VIEW_UNSUPPORTED' if kind == 'unsupported' else
                    'FILE_VIEW_PENDING' if kind in {'pending', 'preparing', 'stopped'} else 'FILE_VIEW_FAILED')
            raise FileViewUnavailableError(row.get('detail') or state.get('error') or state.get('detail')
                                           or 'Guest console References are not ready.', code)
        current = EnvironmentManager(root, environment_id=environment_id).config
        if self._is_closed(key) or current is None:
            raise FileViewUnavailableError('This VM or workspace closed while preparing References.', 'FILE_VIEW_FAILED')
        workspace = await self.workspace(root)
        try:
            policy = await finish_file_view_work(build_references_policy, workspace)
        except (OSError, ValueError) as exc:
            self.request(root, reason='references_source_changed_during_prepare', environment_id=environment_id)
            raise FileViewUnavailableError('The References source changed or became unavailable. Retry after reconciliation.',
                                            'FILE_VIEW_POLICY_CHANGED') from exc
        # A database recovery/removal during the filesystem check invalidates
        # the admitted store; never return a receipt from its old generation.
        if self._is_closed(key) or self.cached_workspace(root) is not workspace:
            raise FileViewUnavailableError('Reopen this workspace before using References.', 'FILE_VIEW_FAILED')
        if row.get('policy_revision') != policy['policy_revision']:
            self.request(root, reason='references_policy_changed_during_prepare', environment_id=environment_id)
            raise FileViewUnavailableError('References changed while its mount was being verified. Retry after reconciliation.',
                                            'FILE_VIEW_POLICY_CHANGED')
        return policy


FILE_VIEWS = FileViewRegistry()
