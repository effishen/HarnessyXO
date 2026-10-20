from __future__ import annotations

import ast
import asyncio
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, unquote, urlparse

from harnessy import __version__
from harnessy.diagnostics import log_event
from harnessy.environment.base import WorkspaceEnvironment


_SOURCE_EXTENSIONS = {
    '.py', '.pyi', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx',
    '.rs', '.go', '.java', '.kt', '.kts', '.cs', '.swift', '.m', '.mm',
    '.json',
}
_SKIP_DIRS = {
    '.git', '.harnessy', '.vendor', '.settings', '__pycache__',
    'node_modules', '.venv', 'venv', 'dist', 'build', '.next', '.cache',
}
_MAX_INDEX_FILE_BYTES = 2_000_000
_MAX_SCAN_FILES = 6000
_IDENTIFIER_RE = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*')


def _output_policy_kwargs(method: Any, output_policy: dict[str, Any] | None) -> dict[str, Any]:
    """A VM integration must accept the shared policy; never silently drop it."""
    if output_policy is None:
        return {}
    return {'output_policy': output_policy}


@dataclass(slots=True)
class Symbol:
    name: str
    kind: str
    path: str
    line: int
    column: int
    end_line: int | None = None
    container: str | None = None
    signature: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'kind': self.kind,
            'path': self.path,
            'line': self.line,
            'column': self.column,
            'end_line': self.end_line,
            'container': self.container,
            'signature': self.signature,
        }


@dataclass(frozen=True, slots=True)
class LanguageServerSpec:
    name: str
    command: tuple[str, ...]
    extensions: frozenset[str]


_LSP_SPECS = (
    LanguageServerSpec('pyright', ('pyright-langserver', '--stdio'), frozenset({'.py', '.pyi'})),
    LanguageServerSpec('pylsp', ('pylsp',), frozenset({'.py', '.pyi'})),
    LanguageServerSpec('typescript-language-server', ('typescript-language-server', '--stdio'), frozenset({'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'})),
    LanguageServerSpec('clangd', ('clangd',), frozenset({'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx', '.m', '.mm'})),
    LanguageServerSpec('rust-analyzer', ('rust-analyzer',), frozenset({'.rs'})),
    LanguageServerSpec('gopls', ('gopls', 'serve'), frozenset({'.go'})),
)


def _path_uri(path: Path) -> str:
    return path.resolve().as_uri()


def _uri_to_path(uri: str) -> Path | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme != 'file':
            return None
        # url2pathname is intentionally avoided to keep dependencies stdlib-only;
        # unquote + Path is sufficient for the local URI forms emitted by LSPs.
        value = unquote(parsed.path)
        if parsed.netloc and not value.startswith('/'):
            value = f'//{parsed.netloc}/{value}'
        elif parsed.netloc:
            value = f'//{parsed.netloc}{value}'
        # Windows file:///C:/... URI -> C:/...
        if len(value) >= 3 and value[0] == '/' and value[2] == ':':
            value = value[1:]
        return Path(value).resolve()
    except Exception:
        return None


def _language_id(path: Path) -> str:
    ext = path.suffix.lower()
    return {
        '.py': 'python', '.pyi': 'python',
        '.js': 'javascript', '.jsx': 'javascriptreact', '.mjs': 'javascript', '.cjs': 'javascript',
        '.ts': 'typescript', '.tsx': 'typescriptreact',
        '.c': 'c', '.h': 'cpp', '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.hh': 'cpp', '.hxx': 'cpp',
        '.rs': 'rust', '.go': 'go', '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin', '.cs': 'csharp', '.swift': 'swift',
        '.m': 'objective-c', '.mm': 'objective-cpp', '.json': 'json',
    }.get(ext, 'plaintext')


class _LSPClient:
    """Tiny sequential JSON-RPC/LSP client whose server runs in the workspace VM.

    The host process is only the fixed environment-controller transport. Language
    server executables, their working directory, and file URIs all live inside
    the guest. HarnessyXO never starts a workspace LSP directly on the host.
    """

    def __init__(
        self,
        root: Path,
        spec: LanguageServerSpec,
        environment: WorkspaceEnvironment,
        *,
        guest_root: str = '/workspace',
        output_policy: dict[str, Any] | None = None,
    ) -> None:
        self.root = root.resolve()
        self.spec = spec
        self.environment = environment
        self.guest_root = '/' + str(guest_root or '/workspace').strip('/')
        self.output_policy = output_policy
        self.proc: asyncio.subprocess.Process | None = None
        self._request_id = 0
        self.notifications: list[dict[str, Any]] = []

    def guest_uri(self, path: Path) -> str:
        target = path.resolve()
        rel = target.relative_to(self.root).as_posix()
        guest = self.guest_root.rstrip('/') + (('/' + rel) if rel not in {'', '.'} else '')
        return 'file://' + quote(guest, safe='/')

    @property
    def root_uri(self) -> str:
        return 'file://' + quote(self.guest_root, safe='/')

    async def _terminate(self, proc: asyncio.subprocess.Process, *, grace: float = 1.5) -> None:
        if proc.returncode is not None:
            return
        try:
            await self.environment.terminate(proc, grace_seconds=grace)
        except Exception:
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    return
                try:
                    await asyncio.shield(asyncio.wait_for(proc.wait(), timeout=2.0))
                except (asyncio.TimeoutError, ProcessLookupError):
                    pass

    async def __aenter__(self) -> '_LSPClient':
        command = shlex.join(self.spec.command)
        self.proc = await self.environment.spawn(
            command, cwd=self.guest_root, active_root=self.root,
            **_output_policy_kwargs(self.environment.spawn, self.output_policy),
        )
        try:
            initialize = await self.request('initialize', {
                'processId': None,
                'rootUri': self.root_uri,
                'workspaceFolders': [{'uri': self.root_uri, 'name': self.root.name or 'workspace'}],
                'capabilities': {
                    'textDocument': {
                        'definition': {'dynamicRegistration': False, 'linkSupport': True},
                        'references': {'dynamicRegistration': False},
                        'publishDiagnostics': {'relatedInformation': True},
                    },
                    'workspace': {'symbol': {'dynamicRegistration': False}},
                },
                'clientInfo': {'name': 'HarnessyXO', 'version': __version__},
            }, timeout=12.0)
            if isinstance(initialize, dict) and initialize.get('_error'):
                raise RuntimeError(str(initialize['_error']))
            await self.notify('initialized', {})
            return self
        except BaseException:
            # __aexit__ is not invoked when __aenter__ fails.
            proc = self.proc
            self.proc = None
            if proc is not None:
                await self._terminate(proc, grace=0.5)
            raise

    async def __aexit__(self, exc_type, exc, tb) -> None:
        proc = self.proc
        if not proc:
            return
        try:
            if proc.returncode is None:
                try:
                    await self.request('shutdown', None, timeout=2.0)
                    await self.notify('exit', None)
                except Exception:
                    pass
            if proc.returncode is None:
                try:
                    await asyncio.wait_for(proc.wait(), timeout=1.5)
                except asyncio.TimeoutError:
                    await self._terminate(proc)
        finally:
            self.proc = None

    async def _write(self, payload: dict[str, Any]) -> None:
        if not self.proc or not self.proc.stdin:
            raise RuntimeError('language server is not running')
        raw = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        framed = f'Content-Length: {len(raw)}\r\n\r\n'.encode('ascii') + raw
        await self.environment.stdin(self.proc, framed)

    async def notify(self, method: str, params: Any) -> None:
        await self._write({'jsonrpc': '2.0', 'method': method, 'params': params})

    async def _read_message(self, timeout: float) -> dict[str, Any]:
        if not self.proc or not self.proc.stdout:
            raise RuntimeError('language server is not running')

        async def read_one() -> dict[str, Any]:
            headers: dict[str, str] = {}
            while True:
                line = await self.proc.stdout.readline()
                if not line:
                    detail = ''
                    if self.proc.stderr:
                        try:
                            detail = (await self.proc.stderr.read()).decode('utf-8', errors='replace').strip()
                        except Exception:
                            detail = ''
                    raise RuntimeError(f'language server closed its output{": " + detail if detail else ""}')
                if line in {b'\r\n', b'\n'}:
                    break
                text = line.decode('ascii', errors='replace').strip()
                if ':' in text:
                    key, value = text.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            length = int(headers.get('content-length') or 0)
            if length <= 0 or length > 32_000_000:
                raise RuntimeError('invalid LSP Content-Length')
            body = await self.proc.stdout.readexactly(length)
            value = json.loads(body.decode('utf-8', errors='replace'))
            return value if isinstance(value, dict) else {'result': value}

        return await asyncio.wait_for(read_one(), timeout=max(0.1, timeout))

    async def request(self, method: str, params: Any, *, timeout: float = 10.0) -> Any:
        self._request_id += 1
        request_id = self._request_id
        await self._write({'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params})
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError(f'LSP request timed out: {method}')
            msg = await self._read_message(remaining)
            if msg.get('id') == request_id:
                if 'error' in msg:
                    return {'_error': msg.get('error')}
                return msg.get('result')
            if 'method' in msg and 'id' in msg:
                await self._write({'jsonrpc': '2.0', 'id': msg['id'], 'result': None})
                continue
            if 'method' in msg:
                self.notifications.append(msg)

    async def open_document(self, path: Path) -> None:
        text = path.read_text('utf-8', errors='replace')
        await self.notify('textDocument/didOpen', {
            'textDocument': {
                'uri': self.guest_uri(path),
                'languageId': _language_id(path),
                'version': 1,
                'text': text,
            }
        })

    async def wait_for_diagnostics(self, uri: str, *, timeout: float = 3.0) -> list[dict[str, Any]]:
        def existing() -> list[dict[str, Any]] | None:
            for msg in reversed(self.notifications):
                if msg.get('method') == 'textDocument/publishDiagnostics':
                    params = msg.get('params') or {}
                    if params.get('uri') == uri:
                        value = params.get('diagnostics')
                        return value if isinstance(value, list) else []
            return None

        already = existing()
        if already is not None:
            return already
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return []
            try:
                msg = await self._read_message(remaining)
            except asyncio.TimeoutError:
                return []
            if 'method' in msg and 'id' in msg:
                await self._write({'jsonrpc': '2.0', 'id': msg['id'], 'result': None})
                continue
            if 'method' in msg:
                self.notifications.append(msg)
                found = existing()
                if found is not None:
                    return found


class CodeIntelligenceService:
    def __init__(
        self, root: Path, *, environment: WorkspaceEnvironment | None = None,
        guest_root: str = '/workspace', allow_host_lsp: bool = False,
        output_policy: dict[str, Any] | None = None,
    ) -> None:
        self.root = root.resolve()
        self.environment = environment
        self.guest_root = '/' + str(guest_root or '/workspace').strip('/')
        self.output_policy = output_policy
        # Kept only as a compatibility keyword for older callers. Workspace
        # intelligence never launches language servers on the host anymore.
        self.allow_host_lsp = False
        self._lsp_available_cache: dict[str, bool] = {}

    # -------------------------------------------------------------- path/index
    def _resolve(self, rel: str | None, *, must_exist: bool = True) -> Path:
        rel = str(rel or '.').strip() or '.'
        value = Path(rel)
        if value.is_absolute():
            raise ValueError('Code intelligence paths must be relative to the active working root')
        target = (self.root / value).resolve(strict=False)
        if target != self.root and self.root not in target.parents:
            raise ValueError('Path escapes the active working root')
        if must_exist and not target.exists():
            raise FileNotFoundError(rel)
        return target

    def _iter_source_files(self, rel: str | None = None) -> Iterable[Path]:
        base = self._resolve(rel or '.', must_exist=True)
        if base.is_file():
            if base.suffix.lower() in _SOURCE_EXTENSIONS and base.stat().st_size <= _MAX_INDEX_FILE_BYTES:
                yield base
            return
        count = 0
        for path in base.rglob('*'):
            if count >= _MAX_SCAN_FILES:
                break
            try:
                resolved = path.resolve(strict=False)
            except (OSError, RuntimeError):
                continue
            if resolved != self.root and self.root not in resolved.parents:
                # A symlinked source file may be lexically inside the workspace
                # while pointing outside it. Never index/read through that link.
                continue
            if not path.is_file() or path.suffix.lower() not in _SOURCE_EXTENSIONS:
                continue
            try:
                rel_parts = path.relative_to(self.root).parts
            except ValueError:
                continue
            if any(part in _SKIP_DIRS for part in rel_parts[:-1]):
                continue
            try:
                if path.stat().st_size > _MAX_INDEX_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            yield path

    def _rel(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    def available_language_servers(self) -> list[dict[str, Any]]:
        if self.environment is None:
            return []
        return [
            {
                'name': spec.name,
                'executable': spec.command[0],
                'extensions': sorted(spec.extensions),
                'environment': 'workspace-vm',
            }
            for spec in _LSP_SPECS
            if self._lsp_available_cache.get(spec.name) is True
        ]

    def _server_for(self, path: Path) -> LanguageServerSpec | None:
        if self.environment is None:
            return None
        ext = path.suffix.lower()
        return next((spec for spec in _LSP_SPECS if ext in spec.extensions), None)

    async def _server_available(self, spec: LanguageServerSpec) -> bool:
        cached = self._lsp_available_cache.get(spec.name)
        if cached is not None:
            return cached
        if self.environment is None:
            self._lsp_available_cache[spec.name] = False
            return False
        try:
            result = await self.environment.exec(
                f'command -v {shlex.quote(spec.command[0])} >/dev/null 2>&1',
                cwd=self.guest_root, timeout=8.0, active_root=self.root,
                **_output_policy_kwargs(self.environment.exec, self.output_policy),
            )
            available = result.returncode == 0
        except Exception:
            available = False
        self._lsp_available_cache[spec.name] = available
        log_event(
            'runtime', 'workspace_lsp_probe', language_server=spec.name,
            available=available, environment='workspace-vm',
        )
        return available

    def _lsp_client(self, spec: LanguageServerSpec) -> _LSPClient:
        if self.environment is None:
            raise RuntimeError('Workspace LSP requires the workspace VM.')
        return _LSPClient(
            self.root, spec, self.environment, guest_root=self.guest_root,
            output_policy=self.output_policy,
        )

    def _lsp_uri(self, path: Path) -> str:
        rel = path.resolve().relative_to(self.root).as_posix()
        guest = self.guest_root.rstrip('/') + (('/' + rel) if rel not in {'', '.'} else '')
        return 'file://' + quote(guest, safe='/')

    def _python_symbols(self, path: Path, text: str) -> list[Symbol]:
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            return []
        rel = self._rel(path)
        out: list[Symbol] = []

        class Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.stack: list[str] = []

            def _add(self, node: ast.AST, name: str, kind: str, signature: str | None = None) -> None:
                out.append(Symbol(
                    name=name,
                    kind=kind,
                    path=rel,
                    line=int(getattr(node, 'lineno', 1)),
                    column=int(getattr(node, 'col_offset', 0)) + 1,
                    end_line=int(getattr(node, 'end_lineno', 0)) or None,
                    container='.'.join(self.stack) or None,
                    signature=signature,
                ))

            def visit_ClassDef(self, node: ast.ClassDef) -> Any:
                self._add(node, node.name, 'class')
                self.stack.append(node.name)
                self.generic_visit(node)
                self.stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
                try:
                    sig = ast.unparse(ast.arguments(posonlyargs=node.args.posonlyargs, args=node.args.args, vararg=node.args.vararg, kwonlyargs=node.args.kwonlyargs, kw_defaults=node.args.kw_defaults, kwarg=node.args.kwarg, defaults=node.args.defaults))
                except Exception:
                    sig = None
                self._add(node, node.name, 'method' if self.stack else 'function', sig)
                self.stack.append(node.name)
                self.generic_visit(node)
                self.stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

        Visitor().visit(tree)
        return out

    def _regex_symbols(self, path: Path, text: str) -> list[Symbol]:
        ext = path.suffix.lower()
        rel = self._rel(path)
        patterns: list[tuple[str, str]] = []
        if ext in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}:
            patterns = [
                ('class', r'\bclass\s+([A-Za-z_$][\w$]*)'),
                ('function', r'\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\('),
                ('function', r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^\n]*\)|[A-Za-z_$][\w$]*)\s*=>'),
                ('interface', r'\binterface\s+([A-Za-z_$][\w$]*)'),
                ('type', r'\btype\s+([A-Za-z_$][\w$]*)\s*='),
            ]
        elif ext in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx', '.m', '.mm'}:
            patterns = [
                ('class', r'\b(?:class|struct)\s+([A-Za-z_]\w*)'),
                ('enum', r'\benum(?:\s+class)?\s+([A-Za-z_]\w*)'),
                ('function', r'^[\t ]*(?:[A-Za-z_][\w:<>,*&\s]*\s+)+([A-Za-z_]\w*)\s*\([^;\n]*\)\s*(?:const\s*)?(?:\{|$)'),
            ]
        elif ext == '.rs':
            patterns = [('function', r'\bfn\s+([A-Za-z_]\w*)'), ('struct', r'\bstruct\s+([A-Za-z_]\w*)'), ('enum', r'\benum\s+([A-Za-z_]\w*)'), ('trait', r'\btrait\s+([A-Za-z_]\w*)')]
        elif ext == '.go':
            patterns = [('function', r'\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\('), ('type', r'\btype\s+([A-Za-z_]\w*)\s+(?:struct|interface)\b')]
        elif ext in {'.java', '.kt', '.kts', '.cs', '.swift'}:
            patterns = [('class', r'\b(?:class|struct|interface|enum|protocol)\s+([A-Za-z_]\w*)'), ('function', r'\b(?:fun|func)\s+([A-Za-z_]\w*)\s*\(')]
        out: list[Symbol] = []
        for kind, pattern in patterns:
            for match in re.finditer(pattern, text, flags=re.MULTILINE):
                name = match.group(1)
                pos = match.start(1)
                line = text.count('\n', 0, pos) + 1
                line_start = text.rfind('\n', 0, pos) + 1
                out.append(Symbol(name=name, kind=kind, path=rel, line=line, column=pos - line_start + 1))
        return out

    def _symbols_in_file(self, path: Path) -> list[Symbol]:
        try:
            text = path.read_text('utf-8', errors='replace')
        except OSError:
            return []
        if path.suffix.lower() in {'.py', '.pyi'}:
            return self._python_symbols(path, text)
        return self._regex_symbols(path, text)

    def _fallback_symbols(self, query: str, rel: str | None, max_results: int) -> list[dict[str, Any]]:
        needle = query.strip().lower()
        exact: list[Symbol] = []
        prefix: list[Symbol] = []
        contains: list[Symbol] = []
        for path in self._iter_source_files(rel):
            for symbol in self._symbols_in_file(path):
                low = symbol.name.lower()
                if not needle or low == needle:
                    exact.append(symbol)
                elif low.startswith(needle):
                    prefix.append(symbol)
                elif needle in low:
                    contains.append(symbol)
                if len(exact) >= max_results and not needle:
                    break
        rows = (exact + prefix + contains)[:max_results]
        return [row.as_dict() for row in rows]

    def _identifier_at(self, path: Path, line: int, column: int) -> str:
        text = path.read_text('utf-8', errors='replace')
        lines = text.splitlines()
        if line < 1 or line > len(lines):
            raise ValueError(f'line must be between 1 and {len(lines)}')
        value = lines[line - 1]
        if not value:
            raise ValueError('No identifier on the requested line')
        idx = max(0, min(column - 1, len(value) - 1))
        # A cursor immediately after an identifier is common in editors.
        if idx >= len(value) or not (value[idx].isalnum() or value[idx] in '_$'):
            if idx > 0 and (value[idx - 1].isalnum() or value[idx - 1] in '_$'):
                idx -= 1
        for match in _IDENTIFIER_RE.finditer(value):
            if match.start() <= idx < match.end():
                return match.group(0)
        raise ValueError('No identifier at the requested line/column')

    def _context_line(self, path: Path, line: int) -> str:
        try:
            lines = path.read_text('utf-8', errors='replace').splitlines()
            return lines[line - 1].strip() if 1 <= line <= len(lines) else ''
        except OSError:
            return ''

    # --------------------------------------------------------------- LSP normalize
    def _location(self, item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        uri = item.get('uri') or item.get('targetUri')
        rng = item.get('range') or item.get('targetSelectionRange') or item.get('targetRange') or {}
        path = _uri_to_path(str(uri or ''))
        if not path:
            return None
        try:
            if self.environment is not None:
                rel = path.relative_to(Path(self.guest_root)).as_posix()
            else:
                rel = path.relative_to(self.root).as_posix()
        except ValueError:
            return None
        start = rng.get('start') or {}
        end = rng.get('end') or {}
        return {
            'path': rel,
            'line': int(start.get('line', 0)) + 1,
            'column': int(start.get('character', 0)) + 1,
            'end_line': int(end.get('line', start.get('line', 0))) + 1,
            'end_column': int(end.get('character', start.get('character', 0))) + 1,
        }

    async def _lsp_position_request(self, path: Path, line: int, column: int, method: str, *, include_declaration: bool = True) -> tuple[str, list[dict[str, Any]]] | None:
        spec = self._server_for(path)
        if not spec or not await self._server_available(spec):
            return None
        try:
            async with self._lsp_client(spec) as client:
                await client.open_document(path)
                params: dict[str, Any] = {
                    'textDocument': {'uri': self._lsp_uri(path)},
                    'position': {'line': max(0, line - 1), 'character': max(0, column - 1)},
                }
                if method == 'textDocument/references':
                    params['context'] = {'includeDeclaration': bool(include_declaration)}
                result = await client.request(method, params, timeout=10.0)
                if isinstance(result, dict) and result.get('_error'):
                    return None
                raw_items = result if isinstance(result, list) else ([result] if isinstance(result, dict) else [])
                locations = [loc for raw in raw_items if (loc := self._location(raw))]
                return f'lsp:{spec.name}', locations
        except (OSError, RuntimeError, asyncio.TimeoutError, json.JSONDecodeError):
            return None

    # ---------------------------------------------------------------- public API
    async def find_symbol(self, query: str, *, path: str | None = None, max_results: int = 50) -> dict[str, Any]:
        query = query.strip()
        if not query:
            raise ValueError('query must not be empty')
        max_results = max(1, min(int(max_results), 200))
        # workspace/symbol can be precise when a language server is known from a
        # supplied file; otherwise the safe multi-language index handles discovery.
        if path:
            target = self._resolve(path, must_exist=True)
            if target.is_file():
                spec = self._server_for(target)
                if spec and await self._server_available(spec):
                    try:
                        async with self._lsp_client(spec) as client:
                            result = await client.request('workspace/symbol', {'query': query}, timeout=10.0)
                            if isinstance(result, list):
                                rows: list[dict[str, Any]] = []
                                for raw in result:
                                    loc = self._location(raw.get('location') if isinstance(raw, dict) else None)
                                    if not loc:
                                        continue
                                    rows.append({
                                        'name': raw.get('name'), 'kind': raw.get('kind'),
                                        'container': raw.get('containerName'), **loc,
                                    })
                                    if len(rows) >= max_results:
                                        break
                                if rows:
                                    return {'ok': True, 'provider': f'lsp:{spec.name}', 'query': query, 'results': rows}
                    except Exception:
                        pass
        rows = self._fallback_symbols(query, path, max_results)
        return {'ok': True, 'provider': 'source-index', 'query': query, 'results': rows}

    async def workspace_symbols(self, query: str = '', *, path: str | None = None, max_results: int = 200) -> dict[str, Any]:
        max_results = max(1, min(int(max_results), 500))
        rows = self._fallback_symbols(query, path, max_results)
        return {
            'ok': True,
            'provider': 'source-index',
            'query': query,
            'path': path or '.',
            'results': rows,
            'language_servers_available': self.available_language_servers(),
        }

    async def go_to_definition(self, path: str, line: int, column: int) -> dict[str, Any]:
        target = self._resolve(path, must_exist=True)
        if not target.is_file():
            raise ValueError('path must be a file')
        identifier = self._identifier_at(target, int(line), int(column))
        lsp = await self._lsp_position_request(target, int(line), int(column), 'textDocument/definition')
        if lsp and lsp[1]:
            provider, locations = lsp
            for row in locations:
                row['preview'] = self._context_line(self.root / row['path'], row['line'])
            return {'ok': True, 'provider': provider, 'identifier': identifier, 'definitions': locations}
        symbols = self._fallback_symbols(identifier, None, 100)
        exact = [row for row in symbols if row.get('name') == identifier]
        exact.sort(key=lambda row: (row.get('path') != self._rel(target), row.get('path', ''), row.get('line', 0)))
        for row in exact:
            row['preview'] = self._context_line(self.root / row['path'], int(row['line']))
        return {'ok': True, 'provider': 'source-index', 'identifier': identifier, 'definitions': exact[:50]}

    async def find_references(self, path: str, line: int, column: int, *, include_declaration: bool = True, max_results: int = 200) -> dict[str, Any]:
        target = self._resolve(path, must_exist=True)
        if not target.is_file():
            raise ValueError('path must be a file')
        max_results = max(1, min(int(max_results), 1000))
        identifier = self._identifier_at(target, int(line), int(column))
        lsp = await self._lsp_position_request(target, int(line), int(column), 'textDocument/references', include_declaration=include_declaration)
        if lsp and lsp[1]:
            provider, locations = lsp
            rows = locations[:max_results]
            for row in rows:
                row['preview'] = self._context_line(self.root / row['path'], row['line'])
            return {'ok': True, 'provider': provider, 'identifier': identifier, 'references': rows, 'truncated': len(locations) > max_results}
        pattern = re.compile(rf'(?<![A-Za-z0-9_$]){re.escape(identifier)}(?![A-Za-z0-9_$])')
        rows: list[dict[str, Any]] = []
        definition_positions = {(row['path'], row['line']) for row in self._fallback_symbols(identifier, None, 200) if row.get('name') == identifier}
        for source in self._iter_source_files():
            try:
                text = source.read_text('utf-8', errors='replace')
            except OSError:
                continue
            rel = self._rel(source)
            for match in pattern.finditer(text):
                line_no = text.count('\n', 0, match.start()) + 1
                if not include_declaration and (rel, line_no) in definition_positions:
                    continue
                line_start = text.rfind('\n', 0, match.start()) + 1
                rows.append({
                    'path': rel,
                    'line': line_no,
                    'column': match.start() - line_start + 1,
                    'preview': self._context_line(source, line_no),
                })
                if len(rows) >= max_results:
                    return {'ok': True, 'provider': 'text-index', 'identifier': identifier, 'references': rows, 'truncated': True}
        return {'ok': True, 'provider': 'text-index', 'identifier': identifier, 'references': rows, 'truncated': False}

    def _fallback_diagnostics_file(self, path: Path) -> list[dict[str, Any]]:
        ext = path.suffix.lower()
        try:
            text = path.read_text('utf-8', errors='replace')
        except OSError as exc:
            return [{'path': self._rel(path), 'severity': 'error', 'message': str(exc), 'line': 1, 'column': 1, 'source': 'HarnessyXO'}]
        if ext in {'.py', '.pyi'}:
            try:
                ast.parse(text, filename=str(path))
            except SyntaxError as exc:
                return [{
                    'path': self._rel(path), 'severity': 'error',
                    'message': exc.msg, 'line': int(exc.lineno or 1),
                    'column': int(exc.offset or 1), 'source': 'python-ast',
                }]
        elif ext == '.json':
            try:
                json.loads(text)
            except json.JSONDecodeError as exc:
                return [{
                    'path': self._rel(path), 'severity': 'error',
                    'message': exc.msg, 'line': exc.lineno, 'column': exc.colno,
                    'source': 'json',
                }]
        return []

    async def diagnostics(self, *, path: str | None = None, max_results: int = 300) -> dict[str, Any]:
        target = self._resolve(path or '.', must_exist=True)
        max_results = max(1, min(int(max_results), 1000))
        if target.is_file():
            spec = self._server_for(target)
            if spec and await self._server_available(spec):
                try:
                    async with self._lsp_client(spec) as client:
                        await client.open_document(target)
                        raw = await client.wait_for_diagnostics(self._lsp_uri(target), timeout=3.0)
                        rows: list[dict[str, Any]] = []
                        severity_names = {1: 'error', 2: 'warning', 3: 'information', 4: 'hint'}
                        for item in raw[:max_results]:
                            rng = item.get('range') or {}
                            start = rng.get('start') or {}
                            rows.append({
                                'path': self._rel(target),
                                'severity': severity_names.get(item.get('severity'), 'unknown'),
                                'message': item.get('message', ''),
                                'line': int(start.get('line', 0)) + 1,
                                'column': int(start.get('character', 0)) + 1,
                                'source': item.get('source') or spec.name,
                                'code': item.get('code'),
                            })
                        return {'ok': True, 'provider': f'lsp:{spec.name}', 'diagnostics': rows, 'truncated': len(raw) > max_results}
                except Exception:
                    pass
        rows: list[dict[str, Any]] = []
        files = [target] if target.is_file() else list(self._iter_source_files(path))
        for source in files:
            rows.extend(self._fallback_diagnostics_file(source))
            if len(rows) >= max_results:
                return {'ok': True, 'provider': 'syntax-fallback', 'diagnostics': rows[:max_results], 'truncated': True}
        return {
            'ok': True,
            'provider': 'syntax-fallback',
            'diagnostics': rows,
            'truncated': False,
            'note': 'Fallback diagnostics currently validate Python syntax and JSON. Install a supported language server inside the workspace VM and pass a matching file for richer diagnostics.',
            'language_servers_available': self.available_language_servers(),
        }
