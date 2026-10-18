"""Read Homebrew's bounded dry-run plan without interpreting warning prose.

Only known CLI action sections count as planned changes. Homebrew has used
both flat formula-name lists and versioned rows; unknown or incomplete plans
remain errors rather than permission to change the host.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Literal


class BrewPlanError(ValueError):
    """A Homebrew plan cannot be verified as the requested prerequisite setup."""


@dataclass(frozen=True)
class BrewPlanEntry:
    name: str
    action: Literal['install', 'upgrade']
    old_version: str = ''
    new_version: str = ''


_NAME = r'[a-z0-9][a-z0-9@+_.-]*(?:/[a-z0-9][a-z0-9@+_.-]*){0,2}'
_NAME_RE = re.compile(_NAME + r'\Z')
_VERSION = r'(?:v?\d|HEAD)[A-Za-z0-9.,_+~:=-]*'
_SIZE = r'(?:\s+\(\d+(?:\.\d+)?\s*(?:B|KB|MB|GB|TB)\))?'
_HEADING = re.compile(
    r'^(?:==>\s*)?Would (install|upgrade) (\d{1,5}) '
    r'(?:formula|formulae|formulas|dependency|dependencies)'
    r'(?: for (' + _NAME + r'))?:\s*$'
)
_VERSION_ROW = re.compile(
    r'^(' + _NAME + r')\s+(' + _VERSION + r')'
    r'(?:\s+->\s+(' + _VERSION + r'))?' + _SIZE + r'\s*$'
)
_MUTATING = re.compile(
    r'^(?:==>\s*)?(?:Would\b|(?:Install(?:ing)?|Upgrad(?:e|ing)|'
    r'Downgrad(?:e|ing)|Remov(?:e|ing)|Reinstall(?:ing)?|Obsolet(?:e|ing)|'
    r'Uninstall(?:ing)?|Link(?:ing)?|Unlink(?:ing)?|Pour(?:ing)?)\b)', re.I
)
_ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_NUMERIC_VERSION = re.compile(r'v?(\d+(?:[.-]\d+)*)(?:_(\d+))?\Z')
_PROTECTED = frozenset({'lima', 'lima-additional-guestagents', 'qemu'})


def canonical_formula_name(value: str) -> str:
    """Keep tap identities, while treating core's optional prefix consistently."""
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise BrewPlanError('Homebrew returned an invalid formula name.')
    return value.removeprefix('homebrew/core/')


def parse_brew_plan(text: str) -> tuple[BrewPlanEntry, ...]:
    """Parse complete install/upgrade sections; never scan warning prose."""
    if not isinstance(text, str) or len(text) > 64000:
        raise BrewPlanError('The Homebrew install plan is missing or too large to verify.')
    text = _ANSI.sub('', text)
    if '\x1b' in text or any(ord(char) < 32 and char not in '\n\r\t' for char in text):
        raise BrewPlanError('The Homebrew install plan contains unsupported control characters.')
    entries: list[BrewPlanEntry] = []
    seen: set[str] = set()
    remaining = 0
    action: Literal['install', 'upgrade'] = 'install'
    warning = False
    sections = 0
    total = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        heading = _HEADING.fullmatch(line)
        if heading:
            if remaining:
                raise BrewPlanError('The Homebrew install plan ended a package section before its stated count.')
            count = int(heading.group(2))
            total += count
            if total > 256:
                raise BrewPlanError('The Homebrew install plan contains too many formulae to verify.')
            action = heading.group(1)  # type: ignore[assignment]
            remaining = count
            warning = False
            sections += 1
            continue
        if _MUTATING.match(line):
            raise BrewPlanError('The Homebrew install plan contains an unsupported package action: ' + line[:160])
        if remaining:
            versioned = _VERSION_ROW.fullmatch(line)
            if versioned:
                name, first, second = versioned.groups()
                rows = [BrewPlanEntry(canonical_formula_name(name), action, first if second else '', second or first)]
            else:
                names = line.split()
                if not names or not all(_NAME_RE.fullmatch(name) for name in names):
                    raise BrewPlanError('The Homebrew install plan contains an unrecognized package row: ' + line[:160])
                rows = [BrewPlanEntry(canonical_formula_name(name), action) for name in names]
            if len(rows) > remaining:
                raise BrewPlanError('The Homebrew install plan lists more packages than its stated count.')
            for entry in rows:
                if entry.name in seen:
                    raise BrewPlanError('The Homebrew install plan repeats formula ' + entry.name + '.')
                seen.add(entry.name)
                entries.append(entry)
            remaining -= len(rows)
            continue
        if line.startswith(('Warning:', 'Note:')):
            warning = True
            continue
        if warning and raw[:1].isspace():
            continue
        if line.startswith('==>'):
            raise BrewPlanError('The Homebrew install plan contains an unrecognized heading: ' + line[:160])
        raise BrewPlanError('The Homebrew install plan contains unrecognized output: ' + line[:160])
    if remaining:
        raise BrewPlanError('The Homebrew install plan is incomplete; its stated package count was not received.')
    if not sections or not entries:
        raise BrewPlanError('Homebrew did not return a complete prerequisite install plan.')
    return tuple(entries)


def _numeric_version(value: str) -> tuple[tuple[int, ...], int] | None:
    if len(value) > 128:
        return None
    match = _NUMERIC_VERSION.fullmatch(value)
    if not match:
        return None
    parts = [int(part) for part in re.split(r'[.-]', match.group(1))]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts), int(match.group(2) or 0)


def validate_brew_plan(
    entries: tuple[BrewPlanEntry, ...],
    installed: dict[str, tuple[str, ...]],
    requested: list[str],
    required_dependencies: set[str],
) -> list[BrewPlanEntry]:
    """Return actual dependency upgrades after checking the prerequisite scope.

    The caller must separately check that no VM is active before applying an
    upgrade. Legacy flat rows omit versions, so installed membership, rather
    than the old section's wording, determines whether they change a formula.
    """
    selected = {canonical_formula_name(name) for name in requested}
    dependencies = {canonical_formula_name(name) for name in required_dependencies}
    if not selected or len(selected) != len(requested):
        raise BrewPlanError('The requested Homebrew prerequisites are empty or repeated.')
    current: dict[str, tuple[str, ...]] = {}
    for name, versions in installed.items():
        name = canonical_formula_name(name)
        if (not isinstance(versions, tuple) or not versions
                or any(not isinstance(version, str) or not version or any(char.isspace() for char in version)
                       for version in versions)):
            raise BrewPlanError('Installed Homebrew versions could not be verified for ' + name + '.')
        if name in current:
            raise BrewPlanError('Installed Homebrew metadata repeats formula ' + name + '.')
        current[name] = versions
    seen: set[str] = set()
    upgrades: list[BrewPlanEntry] = []
    for entry in entries:
        if not isinstance(entry, BrewPlanEntry) or entry.action not in {'install', 'upgrade'}:
            raise BrewPlanError('The Homebrew install plan contains an unsupported package action.')
        name = canonical_formula_name(entry.name)
        if name in seen:
            raise BrewPlanError('The Homebrew install plan repeats formula ' + name + '.')
        seen.add(name)
        if name not in selected | dependencies:
            raise BrewPlanError('The Homebrew install plan includes unrelated formula ' + name + '.')
        versions = current.get(name, ())
        if not versions:
            if entry.action == 'upgrade' or entry.old_version:
                raise BrewPlanError('The Homebrew upgrade plan does not match installed formula ' + name + '.')
            continue
        if name in selected:
            raise BrewPlanError('The requested prerequisite ' + name + ' is already installed; automatic replacement was not allowed.')
        base = name.rsplit('/', 1)[-1].split('@', 1)[0]
        if base in _PROTECTED:
            raise BrewPlanError('The install plan would update VM controller ' + name + '; install its matching version explicitly.')
        if entry.old_version and entry.old_version not in versions:
            raise BrewPlanError('The Homebrew plan and installed versions disagree for ' + name + '.')
        if not entry.new_version:
            raise BrewPlanError('The Homebrew dependency update has no verified target version for ' + name + '.')
        new = _numeric_version(entry.new_version)
        old = [_numeric_version(version) for version in versions]
        if new is None or any(version is None for version in old):
            raise BrewPlanError('Cannot verify the dependency version change for ' + name + '; update it explicitly.')
        if any(new <= version for version in old if version is not None):
            raise BrewPlanError('The Homebrew plan would downgrade or reinstall installed formula ' + name + '.')
        upgrades.append(replace(entry, name=name, action='upgrade'))
    missing = selected - seen
    if missing:
        raise BrewPlanError('The Homebrew install plan omits requested prerequisites: ' + ', '.join(sorted(missing)) + '.')
    return upgrades
