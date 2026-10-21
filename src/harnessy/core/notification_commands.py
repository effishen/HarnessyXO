"""Configurable names for a fixed set of interactive notification actions.

Command names are data, never Python, shell syntax or model instructions.
Disabled, retired and unknown command-shaped messages are always consumed by
the command layer instead of becoming prompts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MAX_COMMAND_TRIGGER_CHARS = 32


@dataclass(frozen=True, slots=True)
class NotificationCommandDefinition:
    id: str
    label: str
    trigger: str
    arguments: str
    description: str


COMMAND_DEFINITIONS = (
    NotificationCommandDefinition('help', 'Help', '.help', '', 'List enabled commands.'),
    NotificationCommandDefinition('chats', 'Recent chats', '.chats', '', 'List recent notified chats and their codes.'),
    NotificationCommandDefinition('use', 'Select chat', '.use', '<code>', 'Select the chat used by later commands.'),
    NotificationCommandDefinition('read', 'Read answer', '.read', '[number]', 'Read the latest answer, or an answer by number.'),
    NotificationCommandDefinition('replies', 'List answers', '.replies', '[page]', 'List the visible answers since your prompt.'),
    NotificationCommandDefinition('history', 'Earlier chat answers', '.history', '[page]', 'Browse earlier visible answers across this chat.'),
    NotificationCommandDefinition('prev', 'Previous answer', '.prev', '', 'Read the previous answer.'),
    NotificationCommandDefinition('next', 'Next answer', '.next', '', 'Read the next answer.'),
    NotificationCommandDefinition('more', 'More answer text', '.more', '', 'Read the next page of a long answer.'),
    NotificationCommandDefinition('stats', 'Run statistics', '.stats', '', 'Show timing, answer counts and available token statistics.'),
    NotificationCommandDefinition('status', 'Run status', '.status', '[code]', 'Show the selected chat or alert status.'),
    NotificationCommandDefinition('reply', 'Reply to model', '.reply', '<text>', 'Send your text to the selected chat.'),
    NotificationCommandDefinition('retry', 'Retry run', '.retry', '[code]', 'Retry the failed run identified by its alert code.'),
)
COMMAND_IDS = tuple(item.id for item in COMMAND_DEFINITIONS)
_BY_ID = {item.id: item for item in COMMAND_DEFINITIONS}
_LEGACY = {'retry': 'retry', 'status': 'status'}


class CommandConfigurationError(ValueError):
    """A useful local settings error without commands, topics or payload text."""


@dataclass(frozen=True, slots=True)
class ParsedNotificationCommand:
    command_id: str
    arguments: str
    trigger: str
    state: str = 'enabled'
    reason: str = ''
    legacy: bool = False


def default_notification_commands() -> dict[str, dict[str, Any]]:
    return {item.id: {'trigger': item.trigger, 'enabled': True} for item in COMMAND_DEFINITIONS}


DEFAULT_NOTIFICATION_COMMANDS = default_notification_commands()


def valid_command_trigger(value: Any) -> bool:
    if (not isinstance(value, str) or not 2 <= len(value) <= MAX_COMMAND_TRIGGER_CHARS
            or value != value.strip() or value[0] not in './!'):
        return False
    word = value[1:]
    return bool(word and word[0].isalpha()
                and all(char.isalnum() or char in '_-' for char in word))


def validate_notification_commands(value: Any) -> dict[str, dict[str, Any]]:
    """Validate editable names, retaining disabled rows in collision checks."""
    if value is None:
        return default_notification_commands()
    if not isinstance(value, dict) or any(key not in _BY_ID for key in value):
        raise CommandConfigurationError('Notification commands must use the listed actions.')
    output = default_notification_commands()
    used: dict[str, str] = {}
    default_owners = {item.trigger.casefold(): item.id for item in COMMAND_DEFINITIONS}
    for item in COMMAND_DEFINITIONS:
        row = value.get(item.id, output[item.id])
        if not isinstance(row, dict) or set(row) - {'trigger', 'enabled'}:
            raise CommandConfigurationError(f'{item.label}: enter a command name and choose On or Off.')
        trigger, enabled = row.get('trigger', item.trigger), row.get('enabled', True)
        if not valid_command_trigger(trigger):
            raise CommandConfigurationError(
                f'{item.label}: start with ., / or !, then use letters, numbers, '
                f'hyphens or underscores. Keep the whole command within {MAX_COMMAND_TRIGGER_CHARS} characters.'
            )
        if not isinstance(enabled, bool):
            raise CommandConfigurationError(f'{item.label}: the command switch must be On or Off.')
        key = trigger.casefold()
        if key in _LEGACY:
            raise CommandConfigurationError('RETRY and STATUS are reserved for existing alert codes. Add a prefix or choose another name.')
        if key in default_owners and default_owners[key] != item.id:
            raise CommandConfigurationError('An original command name stays reserved for its original action. Choose a different name.')
        if key in used:
            raise CommandConfigurationError(f'{item.label} and {_BY_ID[used[key]].label} need different command names, even when disabled.')
        used[key] = item.id
        output[item.id] = {'trigger': trigger, 'enabled': enabled}
    return output


def normalize_notification_commands(value: Any) -> dict[str, dict[str, Any]]:
    """Malformed imported settings disable commands instead of gaining authority."""
    try:
        return validate_notification_commands(value)
    except CommandConfigurationError:
        result = default_notification_commands()
        for item in COMMAND_DEFINITIONS:
            row = value.get(item.id) if isinstance(value, dict) else None
            if isinstance(row, dict) and valid_command_trigger(row.get('trigger')):
                result[item.id]['trigger'] = row['trigger']
            result[item.id]['enabled'] = False
        return result


def notification_command_trigger(config: Any, command_id: str, *, enabled_only: bool = True) -> str:
    raw = config if isinstance(config, dict) else {}
    row = normalize_notification_commands(raw.get('commands')).get(command_id)
    if row is None or (enabled_only and not row['enabled']):
        return ''
    return row['trigger']


def plain_text_reply_allowed(config: Any) -> bool:
    raw = config if isinstance(config, dict) else {}
    return bool(raw.get('plain_text_replies', True) is True
                and normalize_notification_commands(raw.get('commands'))['reply']['enabled'])


def parse_notification_command(text: Any, config: Any) -> ParsedNotificationCommand | None:
    """Parse once without lowercasing, stripping or rewriting the reply body."""
    if not isinstance(text, str):
        return None
    raw = text.lstrip()
    if not raw:
        return None
    end = next((i for i, char in enumerate(raw) if char.isspace()), len(raw))
    trigger = raw[:end]
    rest = raw[end:]
    if rest.startswith('\r\n'):
        arguments = rest[2:]
    else:
        arguments = rest[1:] if rest else ''
    key = trigger.casefold()
    settings = config if isinstance(config, dict) else {}
    commands = normalize_notification_commands(settings.get('commands'))
    for command_id, row in commands.items():
        if row['trigger'].casefold() == key:
            return ParsedNotificationCommand(command_id, arguments, trigger,
                'enabled' if row['enabled'] else 'disabled', '' if row['enabled'] else 'disabled')
    if key in _LEGACY:
        command_id = _LEGACY[key]
        enabled = commands[command_id]['enabled']
        return ParsedNotificationCommand(command_id, arguments, trigger,
            'enabled' if enabled else 'disabled', '' if enabled else 'disabled', legacy=True)
    for item in COMMAND_DEFINITIONS:
        if item.trigger.casefold() == key:
            return ParsedNotificationCommand(item.id, arguments, trigger,
                'unknown' if commands[item.id]['enabled'] else 'disabled', 'renamed')
    if trigger.startswith(('.', '/', '!')):
        return ParsedNotificationCommand('', arguments, trigger, 'unknown', 'unknown')
    return None


def notification_help(config: Any) -> str:
    raw = config if isinstance(config, dict) else {}
    commands = normalize_notification_commands(raw.get('commands'))
    lines = ['HarnessyXO commands']
    for item in COMMAND_DEFINITIONS:
        row = commands[item.id]
        if row['enabled']:
            usage = row['trigger'] + (' ' + item.arguments if item.arguments else '')
            lines.append(usage + ' — ' + item.description)
    if len(lines) == 1:
        lines.append('No commands are enabled. Change them in Notifications settings.')
    if plain_text_reply_allowed(raw):
        lines.append('Plain messages also reply to the selected chat.')
    return '\n'.join(lines)
