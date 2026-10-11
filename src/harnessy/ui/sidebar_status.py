"""Compact sidebar status derived from current leases and durable queue rows."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from harnessy.core.machine import completion_hold_label, completion_wait_reason


@dataclass(frozen=True)
class ChatRunStatus:
    text: str
    icon: str
    detail: str
    tone: str
    action: str = 'chat'


def chat_run_statuses(
    *, slots: list[dict[str, Any]], waiters: list[dict[str, Any]],
    jobs: list[dict[str, Any]], live: dict[str, Any],
    replacement: Any = None, busy: bool = False,
    replacement_blocker_slots: list[dict[str, Any]] | None = None,
    completion_hold: dict[str, Any] | None = None,
    completion_blocker: dict[str, Any] | None = None,
    completion_blocker_slots: list[dict[str, Any]] | None = None,
) -> tuple[ChatRunStatus | None, ChatRunStatus | None]:
    """Return independent current-work and pending-job indicators.

    Only a scheduler lease proves slot ownership. Stored live-state slot values
    and queue ``lane`` fields can survive a finished run and are not assignments.
    Durable queue positions match the Run queue dialog; direct requests have a
    separately labelled scheduler wait position.
    """
    current = None
    pending = [job for job in jobs if job.get('status') == 'pending']
    running = any(job.get('status') == 'running' for job in jobs)
    live = live if live.get('active') and not live.get('finished') else {}
    if slots:
        slots = sorted(slots, key=lambda row: (row.get('kind') == 'subagent', int(row['slot'])))
        slot_text = f"Slot {slots[0]['slot']}" + (f' +{len(slots) - 1}' if len(slots) > 1 else '')
        phase = str(live.get('phase') or '') if live.get('phase_active') else ''
        label = {'prefill': 'PP', 'prompt_processing': 'PP', 'generating': 'Generating',
                 'waiting': 'Waiting'}.get(phase, 'Running')
        if (completion_hold or {}).get('state') == 'checking':
            label = 'Completion Check'
        awaiting_approval = bool(live.get('awaiting_approval')) and not live.get('stopping')
        if awaiting_approval:
            label = 'Needs approval'
        if live.get('stopping'):
            label = 'Stopping'
        details = [f"Agent slot {row['slot']} · " + (
            'temporary subagent' if row.get('kind') == 'subagent' else 'active run'
        ) for row in slots]
        if label == 'PP':
            details.append('Prompt processing (PP)')
        if live.get('status'):
            details.append(str(live['status']))
        if awaiting_approval:
            details.append('Open this Project / Chat to allow or deny the pending tool request. '
                           'Its agent slot remains reserved while it waits.')
        current = ChatRunStatus(
            f'{slot_text} · {label}',
            'pan_tool' if awaiting_approval else 'play_circle_outline',
            '\n'.join(details), 'waiting' if awaiting_approval else 'running',
        )
    elif replacement is not None and replacement.running:
        status = str(replacement.status)
        deleting = bool(getattr(replacement, 'delete_only', False))
        resuming = bool(getattr(replacement, 'resume_from_checkpoint', False))
        stage = 'cancelling' if replacement.cancel_event.is_set() else (
            'restoring' if status.startswith('Restoring') else
            'stopping' if (deleting or resuming) and status.startswith('Stopping') else
            'queueing' if status.startswith('Queueing') else 'waiting'
        )
        detail = ['Checkpoint resume' if resuming else ('Timeline deletion' if deleting else 'Timeline replacement'), status]
        blocker_slots = sorted({int(row['slot']) for row in replacement_blocker_slots or [] if row.get('slot')})
        blockers = list(getattr(replacement, 'waiting_blockers', ()) or ())
        waiting_owner = str(getattr(replacement, 'waiting_owner_id', '') or '')
        waiting_phase = str(getattr(replacement, 'waiting_owner_phase', '') or '')
        phases = {str(row.get('phase') or '') for row in blockers if isinstance(row, dict)}
        if stage == 'waiting' and blocker_slots:
            slot_label = ('Slot ' if len(blocker_slots) == 1 else 'Slots ') + ', '.join(map(str, blocker_slots))
            # This is the blocker's current lease, never the replacement's
            # requested slot or a stale slot remembered by its previous run.
            stage = f'wait {slot_label}'
            detail.append(f'Waiting for the blocking project using {slot_label}.')
        elif stage == 'waiting' and (waiting_phase == 'history' or 'history' in phases):
            stage = 'saving history'
            detail.append('The blocking project is saving history.')
        elif stage == 'waiting' and (waiting_owner or blockers):
            stage = 'waiting for writer'
            detail.append('Waiting for a project writer; no active agent slot was identified for this writer.')
        blocker_labels = list(dict.fromkeys(
            str(row.get('label') or '') for row in blockers if isinstance(row, dict) and row.get('label')
        ))
        if not blocker_labels and getattr(replacement, 'waiting_owner_label', ''):
            blocker_labels = [str(replacement.waiting_owner_label)]
        detail.extend(f'Blocking writer: {label}' for label in blocker_labels)
        detail.append('Deletion does not enter the agent queue or send a model request.' if deleting else
                      ('Restores the selected saved group, then queues continue once.' if resuming else
                       'Global agent queue: not entered yet; a queue number appears after restoration.'))
        action = 'Resume' if resuming else ('Delete' if deleting else 'Replace')
        current = ChatRunStatus(f'{action} · {stage}',
                                'play_arrow' if resuming else ('delete_sweep' if deleting else 'history'),
                                '\n'.join(detail), 'replacement')
    elif live.get('completion_wait_reason') and (completion_blocker is None or completion_blocker):
        reason = (completion_wait_reason(completion_blocker) if completion_blocker
                  else str(live['completion_wait_reason']))
        active_owner = (completion_blocker or {}).get('state') in {'checking', 'continuing', 'running'}
        blocker_slots = sorted({int(row['slot']) for row in completion_blocker_slots or [] if row.get('slot')})
        text = reason
        if active_owner and blocker_slots:
            text = 'Wait · ' + ('Slot ' if len(blocker_slots) == 1 else 'Slots ') + ', '.join(map(str, blocker_slots))
            text += ' · ' + completion_hold_label(str(completion_blocker['state']))
        current = ChatRunStatus(
            text, 'hourglass_top' if active_owner else 'pause_circle_outline',
            reason + '\nThis request has not started and holds no agent slot. '
            + ('The active project keeps its slot until it finishes. This request can be stopped from its chat.'
               if active_owner else 'Open Run queue for recovery controls.'),
            'waiting', 'chat' if active_owner else 'queue',
        )
    elif running:
        current = ChatRunStatus('Run finishing' if not busy else 'Run starting', 'hourglass_top',
                                'Queued run is changing state. No agent slot is currently held.', 'waiting')
    elif waiters and not pending:
        # A direct Send/remote request has no persisted run-queue row.
        waiter = waiters[0]
        position = int(waiter.get('position') or 0)
        slot = int(waiter.get('preferred_slot') or 0)
        preference = f'Slot {slot}' if slot else 'Auto'
        current = ChatRunStatus(
            f'Wait #{position} · {preference}', 'hourglass_top',
            f'Agent-slot wait #{position} (live request)\n'
            + (f'Requested agent slot {slot}; not assigned yet.' if slot else 'Agent slot: Auto (not assigned).'),
            'waiting',
        )
    elif busy and not pending:
        current = ChatRunStatus('Working · no slot yet', 'autorenew',
                                'Project / Chat is working. No agent slot is currently held.', 'waiting')

    queued = None
    if pending:
        first = pending[0]
        slot = int(first.get('preferred_slot') or 0)
        preference = f'Slot {slot}' if slot else 'Auto'
        replacement_id = str(getattr(replacement, 'queued_job_id', '') or '')
        is_replacement = bool(replacement_id and first.get('id') == replacement_id)
        text = f"Q#{first['position']} · {preference}"
        if is_replacement:
            text += ' · Replace'
        if len(pending) > 1:
            text += f' +{len(pending) - 1}'
        details = []
        for job in pending:
            preferred = int(job.get('preferred_slot') or 0)
            detail = f"Global queue #{job['position']} · " + (
                f'requested agent slot {preferred}' if preferred else 'Auto slot'
            )
            if replacement_id and job.get('id') == replacement_id:
                detail += ' · timeline replacement'
            details.append(detail)
        details.append('Pending requests have no assigned slot yet. Open Run queue to view or cancel queued runs.')
        queued = ChatRunStatus(text, 'history' if is_replacement else 'schedule', '\n'.join(details), 'waiting', 'queue')
    return current, queued
