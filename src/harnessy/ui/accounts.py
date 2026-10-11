"""Native account controls embedded in HarnessyXO's Settings dialog.

Passwords are deliberately short-lived widget values, never Settings drafts or
browser storage. The supplied service owns authorization and session checks.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from nicegui import ui

from harnessy.core.auth_account_service import AccountSessionExpired
from harnessy.core.auth_users import UserStoreError


_TITLES = {
    'password': 'Change my password', 'add': 'Add user',
    'reset': 'Reset password', 'enable': 'Enable user',
    'disable': 'Disable user', 'delete': 'Remove user',
}
_SUCCESS = {
    'added': 'User added.', 'reset': 'Password reset.',
    'enabled': 'User enabled.', 'disabled': 'User disabled.',
    'deleted': 'User removed.',
}


class _AccountsPanel:
    def __init__(self, service: Any) -> None:
        self.service = service
        self.busy = False
        self.loading = False
        self.refresh_pending = False
        self.closed = False
        self.expired = False
        self.dialog: Any = None
        self.secret_inputs: list[Any] = []
        self.buttons: list[Any] = []

    def build(self) -> None:
        with ui.column().classes('w-full gap-4') as self.container:
            ui.label('Manage access to this HarnessyXO instance. Account changes apply immediately; '
                     'they do not use the Settings Save button.').classes('text-sm hy-muted')
            with ui.column().classes('hy-settings-section w-full gap-2'):
                ui.label('Your account').classes('font-semibold')
                ui.label(f'Signed in as {self.service.username} · Administrator').classes('text-sm')
                self._button('Change my password', 'password', self.service.username,
                             icon='password')
            with ui.column().classes('hy-settings-section w-full gap-2'):
                with ui.row().classes('w-full items-center gap-2'):
                    ui.label('Users').classes('font-semibold')
                    ui.space()
                    self.refresh_button = ui.button('Refresh', icon='refresh',
                                                    on_click=self.refresh).props('flat dense no-caps')
                    self.buttons.append(self.refresh_button)
                    self._button('Add user', 'add', icon='person_add', filled=True)
                ui.label('All users are administrators with full access to the same workspaces '
                         'and settings. These are not separate or private user spaces.').classes('text-sm hy-muted')
                self.status = ui.label('Loading users…').classes('text-sm hy-muted')
                self.status._props['data-hy-account-status'] = '1'
                self.sign_in = ui.button('Sign in again', on_click=lambda: ui.navigate.to('/login')).props('flat no-caps')
                self.sign_in.set_visibility(False)
                self.users_area = ui.column().classes('w-full gap-2')
            self.timer = ui.timer(0, self.refresh, once=True)

    def _button(self, label: str, action: str, username: str = '', *,
                icon: str | None = None, filled: bool = False) -> Any:
        button = ui.button(label, icon=icon,
                           on_click=lambda: self.open_action(action, username))
        button.props('dense no-caps ' + ('unelevated' if filled else 'flat'))
        button._props.update({'data-hy-account-action': action,
                              'data-hy-account-user': username})
        self.buttons.append(button)
        button.set_enabled(not self.busy and not self.expired)
        return button

    def _clear_passwords(self) -> None:
        for field in self.secret_inputs:
            if not field.is_deleted:
                field.set_value('')

    def close(self) -> None:
        """Clear sensitive inputs when the containing Settings dialog closes."""
        self.closed = True
        self.refresh_pending = False
        self._clear_passwords()
        if self.dialog is not None and not self.dialog.is_deleted:
            self.dialog.close()
        if hasattr(self, 'timer'):
            self.timer.cancel()

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self.buttons = [button for button in self.buttons if not button.is_deleted]
        for button in self.buttons:
            button.set_enabled(not busy and not self.expired)

    def _show_error(self, message: str, *, expired: bool = False) -> None:
        if self.closed or self.container.is_deleted:
            return
        self.status.set_text(message)
        self.status.classes(remove='hy-muted', add='text-negative')
        self.status.set_visibility(True)
        if expired:
            self.expired = True
            self.sign_in.set_visibility(True)
            self._set_busy(False)
            self._clear_passwords()
            self.users_area.clear()
            if self.dialog is not None and not self.dialog.is_deleted:
                self.dialog.close()

    async def refresh(self, *, after_mutation: bool = False) -> None:
        if self.closed or self.expired or self.container.is_deleted or (self.busy and not after_mutation):
            return
        if self.loading:
            # A successful mutation invalidates any in-flight list snapshot.
            # Coalesce refresh requests; the current loader will fetch again
            # before rendering, instead of silently dropping the newer state.
            if after_mutation:
                self.refresh_pending = True
            return
        self.loading = True
        try:
            while not self.closed and not self.expired and not self.container.is_deleted:
                self.refresh_pending = False
                await self._load_users()
                if not self.refresh_pending:
                    break
        finally:
            self.loading = False

    async def _load_users(self) -> None:
        try:
            users = await self.service.list_users()
            if self.closed or self.container.is_deleted or self.refresh_pending:
                return
            self.users_area.clear()
            self.buttons = [button for button in self.buttons if not button.is_deleted]
            with self.users_area:
                for user in users:
                    username = str(user['username'])
                    own = username == self.service.username
                    enabled = bool(user.get('enabled', True))
                    with ui.row().classes('w-full items-center gap-2 py-2') as row:
                        row._props['data-hy-account-row'] = username
                        with ui.column().classes('gap-0 min-w-0'):
                            ui.label(username + (' (you)' if own else '')).classes('font-medium break-all')
                            ui.label('Administrator · ' + ('Enabled' if enabled else 'Disabled')).classes('text-xs hy-muted')
                        ui.space()
                        if not own:
                            self._button('Reset password', 'reset', username, icon='password')
                            self._button('Disable' if enabled else 'Enable',
                                         'disable' if enabled else 'enable', username)
                            self._button('Remove', 'delete', username, icon='person_remove')
            self.status.set_text('No accounts found.' if not users else '')
            self.status.set_visibility(not users)
            self.status.classes(remove='text-negative', add='hy-muted')
        except AccountSessionExpired:
            self._show_error('Your session has ended. Sign in again to manage users.', expired=True)
        except UserStoreError as exc:
            self._show_error(str(exc))
        except (OSError, TimeoutError):
            self._show_error('Account storage is unavailable. Try refreshing again shortly.')

    def open_action(self, action: str, username: str = '') -> None:
        if self.closed or self.busy or self.expired or action not in _TITLES:
            return
        if action in {'reset', 'disable', 'delete'} and username == self.service.username:
            return
        if self.dialog is not None and not self.dialog.is_deleted:
            self._clear_passwords()
            self.dialog.delete()
        self.secret_inputs = []
        inputs: dict[str, Any] = {}

        with ui.dialog().props('persistent') as dialog, ui.card().classes('w-[480px] max-w-[92vw] gap-3'):
            self.dialog = dialog
            dialog._props['data-hy-account-dialog'] = action
            ui.label(_TITLES[action]).classes('text-lg font-semibold')
            if action == 'password':
                ui.label('Changing your password signs this account out on every browser, including '
                         'this one. Any unsaved Settings changes will be lost.').classes('text-sm hy-muted')
            elif action == 'add':
                ui.label('The new user will be an administrator with full access to this HarnessyXO instance.').classes('text-sm hy-muted')
            else:
                ui.label(f'Account: {username}').classes('text-sm font-medium break-all')
                if action in {'reset', 'disable', 'delete'}:
                    ui.label('This will sign this user out of all browsers.').classes('text-sm hy-muted')
                if action == 'delete':
                    ui.label('Only this login is removed. Shared workspaces and chats are kept.').classes('text-sm hy-muted')

            def field(key: str, label: str, *, password: bool = False, autocomplete: str = 'off',
                      max_length: int = 1024) -> Any:
                control = ui.input(label, password=password, password_toggle_button=password).classes('w-full')
                control.props(f'outlined dense autocomplete={autocomplete} maxlength={max_length}')
                control._props['data-hy-account-field'] = key
                inputs[key] = control
                if password:
                    self.secret_inputs.append(control)
                return control

            if action == 'add':
                field('username', 'Username', max_length=64).props('autocapitalize=none spellcheck=false')
                ui.label('Letters, numbers, underscores, dots or hyphens. Usernames are case-insensitive.').classes('text-xs hy-muted')
            if action in {'add', 'reset', 'password'}:
                field('password', 'New password', password=True, autocomplete='new-password')
                field('password_confirm', 'Confirm new password', password=True, autocomplete='new-password')
            if action == 'delete':
                field('confirm_delete', f'Type {username} to confirm removal', max_length=64)
            field('current_password', 'Your current password', password=True, autocomplete='current-password')
            ui.label('Confirm with the password of your own signed-in account.').classes('text-xs hy-muted')
            error = ui.label('').classes('text-sm text-negative')
            error._props['data-hy-account-error'] = '1'
            error.set_visibility(False)

            async def submit() -> None:
                if self.busy or self.closed or self.expired:
                    return
                form = {key: str(control.value or '') for key, control in inputs.items()}
                if action not in {'add', 'password'}:
                    form['username'] = username
                # Clear widgets before awaiting KDF or storage, including failures.
                self._clear_passwords()
                self._set_busy(True)
                confirm.disable()
                cancel.disable()
                error.set_visibility(False)
                try:
                    result = await self.service.mutate(action, form)
                    if result == 'password_changed':
                        with self.container.client:
                            ui.navigate.to('/login?notice=password_changed')
                        return
                    if self.closed or self.container.is_deleted:
                        return
                    dialog.close()
                    with self.container:
                        ui.notify(_SUCCESS.get(result, 'Account updated.'), type='positive')
                    await self.refresh(after_mutation=True)
                except AccountSessionExpired:
                    self._show_error('Your session has ended. Sign in again to manage users.', expired=True)
                except UserStoreError as exc:
                    if not self.closed and not error.is_deleted:
                        error.set_text(str(exc))
                        error.set_visibility(True)
                except (OSError, TimeoutError):
                    if not self.closed and not error.is_deleted:
                        error.set_text('The account operation could not be confirmed. Refresh the user list '
                                       'before trying again; it may still finish.')
                        error.set_visibility(True)
                finally:
                    form.clear()
                    self._clear_passwords()
                    self._set_busy(False)
                    if not confirm.is_deleted:
                        confirm.set_enabled(not self.expired)
                    if not cancel.is_deleted:
                        cancel.enable()

            with ui.row().classes('w-full justify-end gap-2'):
                cancel = ui.button('Cancel', on_click=dialog.close).props('flat no-caps')
                cancel._props['data-hy-account-cancel'] = '1'
                confirm = ui.button(_TITLES[action], on_click=submit).props('unelevated no-caps')
                confirm._props['data-hy-account-submit'] = action
                if action == 'delete':
                    confirm.props('color=negative')
            dialog.on_value_change(lambda event: self._clear_passwords() if not event.value else None)
        dialog.open()


def build_accounts_panel(service: Any) -> Callable[[], None]:
    """Build the Settings tab and return a close hook for its containing dialog."""
    panel = _AccountsPanel(service)
    panel.build()
    return panel.close
