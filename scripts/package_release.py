#!/usr/bin/env python3
"""Build committed application files and verify a matching public GitHub release."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
import zipfile


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'effishen/HarnessyXO'
REPOSITORY_ID = 1414695489
MANIFEST_NAME = 'RELEASE_MANIFEST.json'
ROOT_FILES = {
    '.gitignore', 'CHANGELOG.md', 'FEATURES.md', 'LICENSE', 'README.md', 'VERSION',
    'harnessy_app.py', 'harnessy_update.py', 'requirements.txt', 'run.py',
    'run_harnessy.sh',
}
BUILD_FILES = {'.github/workflows/release.yml', 'scripts/package_release.py'}
SKILLS = {
    'bug-fix', 'codebase-investigation', 'implementation',
    'large-attachment-analysis', 'project-handover', 'refactor',
    'release-packaging', 'web-research',
}
EXPECTED_MARKDOWN = {'README.md', 'FEATURES.md', 'CHANGELOG.md'} | {
    f'skills/{name}/SKILL.md' for name in SKILLS
}
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class ReleaseError(RuntimeError):
    pass


def run(command: list[str], *, timeout: int = 120) -> bytes:
    result = subprocess.run(command, cwd=ROOT, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise ReleaseError(f'{command[0]} failed (exit {result.returncode}).')
    return result.stdout


def git(*arguments: str) -> bytes:
    return run(['git', *arguments])


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> bytes:
    payload = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')
    path.write_bytes(payload)
    return payload


def allowed_path(name: str) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or '\\' in name or any(p in {'', '.', '..'} for p in path.parts):
        return False
    if any(p.startswith('.') for p in path.parts) and name not in ROOT_FILES | BUILD_FILES:
        return False
    forbidden = {'tests', 'qa', 'upload', 'diagnostics', '__pycache__',
                 'node_modules', 'dist', 'runtime', 'credentials'}
    for index, component in enumerate(path.parts[:-1]):
        # src/harnessy/diagnostics is application code, not exported diagnostic data.
        application_diagnostics = (index == 2 and path.parts[:3]
                                   == ('src', 'harnessy', 'diagnostics'))
        if component.casefold() in forbidden and not application_diagnostics:
            return False
    if path.suffix.casefold() in {'.pyc', '.db', '.sqlite', '.sqlite3', '.zip',
                                  '.log', '.pem', '.key', '.p12', '.pfx'}:
        return False
    return name in ROOT_FILES | BUILD_FILES or name.startswith(('src/', 'skills/'))


def committed_files(commit: str) -> dict[str, tuple[bytes, int, str]]:
    files: dict[str, tuple[bytes, int, str]] = {}
    total = 0
    for entry in git('ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not entry:
            continue
        metadata, raw_name = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode('ascii').split()
        name = raw_name.decode('utf-8', errors='strict')
        if not allowed_path(name):
            raise ReleaseError(f'Tracked file is outside the application package: {name}')
        if kind != 'blob' or mode not in {'100644', '100755'}:
            raise ReleaseError(f'Only regular application files can be packaged: {name}')
        size = int(git('cat-file', '-s', blob))
        total += size
        if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ReleaseError('Application package exceeds its size limit.')
        files[name] = (git('cat-file', 'blob', blob), int(mode, 8), blob)
    missing = (ROOT_FILES | BUILD_FILES) - files.keys()
    if missing:
        raise ReleaseError('Required application files are missing: ' + ', '.join(sorted(missing)))
    markdown = {name for name in files if name.lower().endswith('.md')}
    if markdown != EXPECTED_MARKDOWN:
        raise ReleaseError('Package must contain the three living documents and eight functional skills.')
    if not files['run_harnessy.sh'][1] & stat.S_IXUSR:
        raise ReleaseError('run_harnessy.sh must be executable in the Git tree.')
    return files


def release_notes(changelog: bytes, version: str) -> str:
    text = changelog.decode('utf-8')
    headings = list(re.finditer(r'^## (v[^\s]+)\s*$', text, re.MULTILINE))
    if not headings or headings[0].group(1) != f'v{version}':
        raise ReleaseError('The current VERSION must be the first release in CHANGELOG.md.')
    if sum(match.group(1) == f'v{version}' for match in headings) != 1:
        raise ReleaseError('The current changelog version must appear exactly once.')
    end = headings[1].start() if len(headings) > 1 else len(text)
    body = text[headings[0].end():end].strip()
    if not body or not re.search(r'^- \S', body, re.MULTILINE):
        raise ReleaseError('The current release needs concrete, nonempty changelog notes.')
    return f'## v{version}\n\n{body}\n'


def build(output: Path, revision: str, expected_commit: str | None = None) -> dict:
    (output / 'publication-proof.json').unlink(missing_ok=True)
    commit = git('rev-parse', '--verify', f'{revision}^{{commit}}').decode('ascii').strip()
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ReleaseError('A full Git commit identity is required.')
    if expected_commit and commit != expected_commit:
        raise ReleaseError('The checkout is not the workflow commit.')
    files = committed_files(commit)
    version = files['VERSION'][0].decode('ascii').strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ReleaseError('VERSION must be a stable major.minor.patch release.')
    init = ast.parse(files['src/harnessy/__init__.py'][0], filename='src/harnessy/__init__.py')
    versions = [node.value.value for node in init.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == '__version__'
                        for target in node.targets)
                and isinstance(node.value, ast.Constant)]
    if versions != [version]:
        raise ReleaseError('VERSION and harnessy.__version__ differ.')
    python_count = 0
    for name, (data, _mode, _blob) in files.items():
        if name.endswith('.py'):
            compile(data, name, 'exec', dont_inherit=True)
            python_count += 1
    notes = release_notes(files['CHANGELOG.md'][0], version)
    output.mkdir(parents=True, exist_ok=True)
    manifest = {
        'schema': 'harnessyxo-release-manifest-v1', 'version': version,
        'source_commit': commit,
        'files': {name: {'sha256': sha256(data), 'size': len(data),
                         'mode': f'{mode:o}', 'git_blob': blob}
                  for name, (data, mode, blob) in sorted(files.items())},
    }
    manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('utf-8')
    archive = output / f'HarnessyXO_v{version}.zip'
    timestamp = int(git('show', '-s', '--format=%ct', commit))
    date = time.gmtime(max(315532800, min(timestamp, 4354819198)))[:6]
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, (data, mode, _blob) in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=date)
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, data, compresslevel=9)
        info = zipfile.ZipInfo(MANIFEST_NAME, date_time=date)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        bundle.writestr(info, manifest_data, compresslevel=9)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() or set(bundle.namelist()) != set(files) | {MANIFEST_NAME}:
            raise ReleaseError('Release ZIP failed its integrity check.')
        for name, (data, mode, _blob) in files.items():
            if bundle.read(name) != data or bundle.getinfo(name).external_attr >> 16 != mode:
                raise ReleaseError(f'Release ZIP does not match its committed source: {name}')
    digest = sha256(archive.read_bytes())
    checksum = output / f'{archive.name}.sha256'
    checksum.write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    (output / 'release-notes.md').write_text(notes, encoding='utf-8')
    metadata = {
        'schema': 'harnessyxo-release-build-v1', 'version': version, 'tag': f'v{version}',
        'commit': commit, 'zip_name': archive.name, 'zip_sha256': digest,
        'zip_size': archive.stat().st_size, 'checksum_name': checksum.name,
        'checksum_sha256': sha256(checksum.read_bytes()),
        'notes_sha256': sha256(notes.encode('utf-8')), 'file_count': len(files) + 1,
        'markdown_count': len(EXPECTED_MARKDOWN), 'python_count': python_count,
        'manifest_sha256': sha256(manifest_data),
    }
    write_json(output / 'build-metadata.json', metadata)
    return metadata


def gh_json(endpoint: str, *, method: str = 'GET', fields: dict | None = None,
            missing_ok: bool = False) -> dict | None:
    command = ['gh', 'api', '--method', method, endpoint,
               '-H', 'Accept: application/vnd.github+json',
               '-H', 'X-GitHub-Api-Version: 2022-11-28']
    for name, value in (fields or {}).items():
        command.extend(['-f', f'{name}={value}'])
    result = subprocess.run(command, cwd=ROOT, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        if missing_ok and b'HTTP 404' in result.stderr:
            return None
        raise ReleaseError(f'GitHub API {method} failed (exit {result.returncode}).')
    return json.loads(result.stdout)


def tag_target(repository: str, tag: str) -> str | None:
    ref = gh_json(f'repos/{repository}/git/ref/tags/{tag}', missing_ok=True)
    if ref is None:
        return None
    target = ref['object']
    for _ in range(8):
        if target['type'] == 'commit':
            return target['sha']
        if target['type'] != 'tag':
            break
        target = gh_json(f'repos/{repository}/git/tags/{target["sha"]}')['object']
    raise ReleaseError('Release tag does not resolve to a Git commit.')


def release_identity(release: dict) -> dict:
    return {
        'release': {name: release.get(name) for name in
                    ('id', 'tag_name', 'name', 'body', 'draft', 'prerelease',
                     'published_at', 'immutable')},
        'assets': sorted(
            [{name: asset.get(name) for name in ('id', 'name', 'size', 'state', 'digest')}
             for asset in release.get('assets', [])], key=lambda asset: asset['name']),
    }


def publish(output: Path, repository: str, expected_commit: str) -> dict:
    (output / 'publication-proof.json').unlink(missing_ok=True)
    if repository != REPOSITORY:
        raise ReleaseError('This publication workflow is bound to effishen/HarnessyXO.')
    metadata = json.loads((output / 'build-metadata.json').read_text('utf-8'))
    if metadata['commit'] != expected_commit:
        raise ReleaseError('The prepared package is not the workflow commit.')
    expected_files = {}
    for filename, expected in [(metadata['zip_name'], metadata['zip_sha256']),
                               (metadata['checksum_name'], metadata['checksum_sha256']),
                               ('release-notes.md', metadata['notes_sha256'])]:
        payload = (output / filename).read_bytes()
        if sha256(payload) != expected:
            raise ReleaseError('A prepared release file changed after packaging.')
        expected_files[filename] = {'size': len(payload), 'sha256': expected}
        if filename == 'release-notes.md':
            notes = payload.decode('utf-8')
    repo = gh_json(f'repos/{repository}')
    if (repo['id'] != REPOSITORY_ID or repo['full_name'] != repository
            or repo.get('private') is not False or repo.get('visibility') != 'public'):
        raise ReleaseError('The intended public repository identity was not verified.')
    commit = metadata['commit']
    tag = metadata['tag']
    target = tag_target(repository, tag)
    if target is not None and target != commit:
        raise ReleaseError('The existing version tag points to another commit. Publish a new version.')
    if target is None:
        gh_json(f'repos/{repository}/git/refs', method='POST',
                fields={'ref': f'refs/tags/{tag}', 'sha': commit})
    if tag_target(repository, tag) != commit:
        raise ReleaseError('The published tag does not point to the intended commit.')
    release = gh_json(f'repos/{repository}/releases/tags/{tag}', missing_ok=True)
    if release is None:
        # --verify-tag prevents implicit tagging; no edit, delete or --clobber path exists.
        run(['gh', 'release', 'create', tag, str(output / metadata['zip_name']),
             str(output / metadata['checksum_name']), '--repo', repository, '--verify-tag',
             '--target', commit, '--title', f'HarnessyXO {tag}',
             '--notes-file', str(output / 'release-notes.md')], timeout=300)
        release = gh_json(f'repos/{repository}/releases/tags/{tag}')
    if (release['tag_name'] != tag or release['name'] != f'HarnessyXO {tag}'
            or release.get('draft') is not False or release.get('prerelease') is not False
            or release.get('body', '').strip() != notes.strip()
            or not release.get('published_at')):
        raise ReleaseError('Existing release metadata differs. No release was overwritten.')
    assets = release.get('assets', [])
    names = [asset['name'] for asset in assets]
    if sorted(names) != sorted([metadata['zip_name'], metadata['checksum_name']]):
        raise ReleaseError('Release assets differ. No existing assets were overwritten.')
    verified_assets = []
    with tempfile.TemporaryDirectory(prefix='harnessy-release-readback-') as temporary:
        for asset in assets:
            expected = expected_files[asset['name']]
            if asset.get('state') != 'uploaded' or asset.get('size') != expected['size']:
                raise ReleaseError('Published asset size or upload state differs.')
            downloaded = Path(temporary) / asset['name']
            with downloaded.open('wb') as stream:
                result = subprocess.run(
                    ['gh', 'api', f'repos/{repository}/releases/assets/{asset["id"]}',
                     '-H', 'Accept: application/octet-stream',
                     '-H', 'X-GitHub-Api-Version: 2022-11-28'],
                    cwd=ROOT, check=False, stdout=stream, stderr=subprocess.PIPE, timeout=180)
            if result.returncode or downloaded.stat().st_size != expected['size']:
                raise ReleaseError('Published asset download failed its size check.')
            digest = sha256(downloaded.read_bytes())
            if digest != expected['sha256']:
                raise ReleaseError('Downloaded release asset differs from the prepared package.')
            verified_assets.append({'name': asset['name'], 'id': asset['id'],
                                    'size': asset['size'], 'sha256': digest,
                                    'download_verified': True,
                                    'url': asset['browser_download_url']})
    if tag_target(repository, tag) != commit:
        raise ReleaseError('The release tag changed during publication verification.')
    final_release = gh_json(f'repos/{repository}/releases/tags/{tag}')
    if release_identity(final_release) != release_identity(release):
        raise ReleaseError('Release metadata changed during publication verification.')
    final_repo = gh_json(f'repos/{repository}')
    if (final_repo['id'] != REPOSITORY_ID or final_repo['full_name'] != repository
            or final_repo.get('private') is not False or final_repo.get('visibility') != 'public'):
        raise ReleaseError('Public repository identity changed during publication verification.')
    proof = {
        'schema': 'harnessyxo-release-proof-v1', 'verified': True,
        'repository': repository, 'repository_id': repo['id'],
        'private': repo['private'], 'visibility': repo['visibility'],
        'version': metadata['version'], 'tag': tag, 'tag_target_commit': commit,
        'release': {'id': release['id'], 'url': release['html_url'],
                    'name': release['name'], 'body': release['body'],
                    'body_sha256': sha256(release['body'].encode('utf-8')),
                    'published_at': release['published_at'],
                    'immutable': release.get('immutable', False)},
        'assets': verified_assets, 'package': metadata,
        'workflow_run_id': os.environ.get('GITHUB_RUN_ID'),
    }
    write_json(output / 'publication-proof.json', proof)
    return proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('build', 'publish'))
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--commit', default='HEAD')
    parser.add_argument('--expected-commit')
    parser.add_argument('--repository', default=REPOSITORY)
    arguments = parser.parse_args()
    try:
        if arguments.command == 'build':
            result = build(arguments.output.resolve(), arguments.commit, arguments.expected_commit)
            print(f'Built {result["zip_name"]}: {result["file_count"]} files, '
                  f'{result["markdown_count"]} Markdown, SHA-256 {result["zip_sha256"]}.')
        else:
            if not arguments.expected_commit:
                raise ReleaseError('Publication requires --expected-commit.')
            result = publish(arguments.output.resolve(), arguments.repository, arguments.expected_commit)
            print(f'Verified public release: {result["release"]["url"]}')
    except (ReleaseError, OSError, ValueError, KeyError, SyntaxError,
            subprocess.SubprocessError) as error:
        parser.exit(1, f'Release stopped: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
