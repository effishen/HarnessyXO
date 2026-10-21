"""Editable notification command names and individual action switches."""
from __future__ import annotations

import inspect
from typing import Any, Callable

from nicegui import ui

from harnessy.core.notification_commands import (
    COMMAND_DEFINITIONS,
    CommandConfigurationError,
    default_notification_commands,
    normalize_notification_commands,
    notification_help,
    validate_notification_commands,
)


class NotificationCommandEditor:
    """Keep the user's draft intact so invalid command names cannot be saved."""

    def __init__(self, config: Any = None, on_change: Callable[[], Any] | None = None) -> None:
        raw = config if isinstance(config, dict) else {}
        commands = normalize_notification_commands(raw.get('commands'))
        self.on_change = on_change
        self.trigger_inputs: dict[str, Any] = {}
        self.enabled_switches: dict[str, Any] = {}
        self._ready = False
        with ui.column().classes('w-full min-w-0 gap-2').style('max-width:100%').props(
            'data-hy-notification-commands=1',
        ) as self.container:
            ui.label('Notification commands').classes('font-semibold text-sm')
            ui.label(
                'Rename commands and turn individual actions on or off. '
                'Start command names with ., / or !. Names are not case sensitive.'
            ).classes('text-xs hy-muted').style('overflow-wrap:anywhere')
            with ui.column().classes('w-full min-w-0 gap-1'):
                for definition in COMMAND_DEFINITIONS:
                    row = commands[definition.id]
                    with ui.column().classes('w-full min-w-0 gap-0 py-2').style(
                        'border-bottom:1px solid rgba(128,128,128,.18);max-width:100%',
                    ).props(f'data-hy-notification-command={definition.id}'):
                        with ui.row().classes('w-full min-w-0 items-center gap-2 flex-wrap'):
                            switch = ui.switch(definition.label, value=row['enabled']).classes(
                                'text-sm min-w-0 grow',
                            ).style('overflow-wrap:anywhere').props(
                                f'aria-label="{definition.label} enabled" '
                                f'data-hy-notification-command-enabled={definition.id}',
                            )
                            trigger = ui.input('Command', value=row['trigger']).classes(
                                'min-w-0',
                            ).style('width:166px;max-width:100%').props(
                                'outlined dense maxlength=32 '
                                f'aria-label="{definition.label} command" '
                                f'data-hy-notification-command-trigger={definition.id}',
                            )
                        suffix = f' Arguments: {definition.arguments}.' if definition.arguments else ''
                        ui.label(definition.description + suffix).classes(
                            'w-full text-xs hy-muted',
                        ).style('overflow-wrap:anywhere')
                        self.trigger_inputs[definition.id] = trigger
                        self.enabled_switches[definition.id] = switch
                        trigger.on_value_change(self._changed)
                        switch.on_value_change(self._changed)
            self.plain_switch = ui.switch(
                'Allow plain messages as model replies',
                value=raw.get('plain_text_replies', True) is True,
            ).classes('w-full min-w-0 text-sm').style('overflow-wrap:anywhere').props(
                'data-hy-notification-plain-replies=1',
            )
            self.plain_note = ui.label('').classes('text-xs hy-muted').style('overflow-wrap:anywhere')
            self.plain_switch.on_value_change(self._changed)
            self.error = ui.label('').classes('w-full text-xs text-negative').style(
                'white-space:pre-wrap;overflow-wrap:anywhere',
            ).props('role=status data-hy-notification-command-error=1')
            with ui.expansion('Help preview', icon='help_outline').classes('w-full min-w-0'):
                self.preview = ui.label('').classes('w-full text-xs').style(
                    'white-space:pre-wrap;overflow-wrap:anywhere;max-width:100%',
                ).props('data-hy-notification-command-preview=1')
            ui.button('Reset command names and switches', on_click=self.reset_defaults).props(
                'flat dense no-caps data-hy-notification-command-reset=1',
            ).classes('max-w-full').style('white-space:normal')
        self._ready = True
        self.refresh()

    @property
    def plain_text_replies(self) -> bool:
        """Return the stored preference; Reply's switch also gates it at runtime."""
        return self.plain_switch.value is True

    def value(self) -> dict[str, dict[str, Any]]:
        return {
            definition.id: {
                'trigger': self.trigger_inputs[definition.id].value,
                'enabled': self.enabled_switches[definition.id].value,
            }
            for definition in COMMAND_DEFINITIONS
        }

    def validate(self) -> dict[str, dict[str, Any]]:
        return validate_notification_commands(self.value())

    def refresh(self) -> None:
        reply_enabled = self.enabled_switches['reply'].value is True
        self.plain_switch.set_enabled(reply_enabled)
        self.plain_note.set_text(
            'Messages without a command are sent to the selected chat. Command-shaped '
            'messages are handled by the menu.' if reply_enabled else
            'Plain message replies are unavailable while Reply to model is off. '
            'Your preference is retained.'
        )
        try:
            commands = self.validate()
        except CommandConfigurationError as exc:
            self.error.set_text(str(exc))
            self.preview.set_text('Fix the command settings above to preview help.')
            return
        self.error.set_text('')
        self.preview.set_text(notification_help({
            'commands': commands, 'plain_text_replies': self.plain_text_replies,
        }))

    async def _changed(self, _event: Any = None) -> None:
        if not self._ready:
            return
        self.refresh()
        if self.on_change is not None:
            result = self.on_change()
            if inspect.isawaitable(result):
                await result

    async def reset_defaults(self) -> None:
        self._ready = False
        try:
            for command_id, row in default_notification_commands().items():
                self.trigger_inputs[command_id].set_value(row['trigger'])
                self.enabled_switches[command_id].set_value(row['enabled'])
        finally:
            self._ready = True
        await self._changed()
