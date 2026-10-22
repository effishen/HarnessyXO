"""Portable, inert, paginated PDF rendering of selected saved chat sections.

The domain layer supplies only the content the user selected. This renderer
never opens attachment paths, loads Markdown images, or creates active links.
"""
from __future__ import annotations

import html
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, LongTable, PageTemplate, Paragraph,
    Spacer, TableStyle,
)

from .print_export import PrintExportCancelled


_FONT_LOCK = threading.Lock()
_FONTS: tuple[str, str, str, str] | None = None
_FALLBACK_FONT: str | None = None
_PAGE_WIDTH, _PAGE_HEIGHT = A4
_MARGIN = 43.0
_WIDTH = _PAGE_WIDTH - 2 * _MARGIN
_INK = colors.HexColor('#17232c')
_MUTED = colors.HexColor('#53636c')
_BORDER = colors.HexColor('#d4dce0')
_ACCENT = colors.HexColor('#087d72')
_CODE_BG = colors.HexColor('#f3f5f6')
_MAX_SECTIONS = 200_000
_MAX_RENDER_TEXT = 64 * 1024 * 1024
_MAX_FLOWABLES = 250_000
_PARAGRAPH_CHARS = 4000


def _cancelled(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise PrintExportCancelled('PDF export cancelled.')


def _first_font(paths: Iterable[Path], fallback: Path) -> Path:
    for path in paths:
        if path.is_absolute() and path.is_file():
            return path
    return fallback


def _fonts() -> tuple[str, str, str, str]:
    """Use known local Unicode fonts, with licensed bundled Vera fallbacks."""
    global _FONTS, _FALLBACK_FONT
    with _FONT_LOCK:
        if _FONTS is not None:
            return _FONTS
        bundled = Path(reportlab.__file__).resolve().parent / 'fonts'
        regular = _first_font((
            Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
            Path('/usr/share/fonts/dejavu/DejaVuSans.ttf'),
            Path('/System/Library/Fonts/Supplemental/Arial.ttf'),
            Path('/Library/Fonts/Arial.ttf'),
            Path('C:/Windows/Fonts/arial.ttf'),
        ), bundled / 'Vera.ttf')
        bold = _first_font((
            Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'),
            Path('/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf'),
            Path('/System/Library/Fonts/Supplemental/Arial Bold.ttf'),
            Path('/Library/Fonts/Arial Bold.ttf'),
            Path('C:/Windows/Fonts/arialbd.ttf'),
        ), bundled / 'VeraBd.ttf')
        italic = _first_font((
            Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf'),
            Path('/usr/share/fonts/dejavu/DejaVuSans-Oblique.ttf'),
            Path('/System/Library/Fonts/Supplemental/Arial Italic.ttf'),
            Path('/Library/Fonts/Arial Italic.ttf'),
            Path('C:/Windows/Fonts/ariali.ttf'),
        ), bundled / 'VeraIt.ttf')
        mono = _first_font((
            Path('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'),
            Path('/usr/share/fonts/dejavu/DejaVuSansMono.ttf'),
            Path('/System/Library/Fonts/Menlo.ttc'),
            Path('C:/Windows/Fonts/consola.ttf'),
            Path('C:/Windows/Fonts/cour.ttf'),
        ), bundled / 'Vera.ttf')
        for name, path in (
            ('HyPrint', regular), ('HyPrintBold', bold),
            ('HyPrintItalic', italic), ('HyPrintMono', mono),
        ):
            try:
                pdfmetrics.registerFont(TTFont(name, str(path), subfontIndex=0))
            except Exception:
                # A host font can be unreadable or an unsupported collection.
                fallback = bundled / ('VeraBd.ttf' if name.endswith('Bold') else
                                      'VeraIt.ttf' if name.endswith('Italic') else 'Vera.ttf')
                pdfmetrics.registerFont(TTFont(name, str(fallback)))
        pdfmetrics.registerFontFamily('HyPrint', normal='HyPrint', bold='HyPrintBold',
                                     italic='HyPrintItalic', boldItalic='HyPrintBold')
        # Embed actual glyph outlines if a known multilingual host font exists.
        # Standard CID font names alone rely on a viewer's font pack and can
        # silently render empty boxes on another machine.
        for fallback in (
            Path('/System/Library/Fonts/Supplemental/Arial Unicode.ttf'),
            Path('/Library/Fonts/Arial Unicode.ttf'),
            Path('/System/Library/Fonts/STHeiti Light.ttc'),
            Path('/System/Library/Fonts/PingFang.ttc'),
            Path('C:/Windows/Fonts/msyh.ttc'),
            Path('C:/Windows/Fonts/msgothic.ttc'),
            Path('/usr/share/fonts/truetype/wqy/wqy-microhei.ttc'),
            Path('/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc'),
            Path('/usr/share/fonts/truetype/noto/NotoSansSC-Regular.ttf'),
        ):
            if not fallback.is_absolute() or not fallback.is_file():
                continue
            try:
                pdfmetrics.registerFont(TTFont('HyPrintFallback', str(fallback), subfontIndex=0))
                _FALLBACK_FONT = 'HyPrintFallback'
                break
            except Exception:
                continue
        _FONTS = ('HyPrint', 'HyPrintBold', 'HyPrintItalic', 'HyPrintMono')
        return _FONTS


@dataclass
class _Text:
    unsupported: dict[int, int] = field(default_factory=dict)

    def markup(self, text: Any, font: str = 'HyPrint', *, spaces: bool = False) -> str:
        """Escape source markup and choose a font for every printable scalar."""
        text = str(text or '')
        widths = pdfmetrics.getFont(font).face.charWidths
        fallback_widths = pdfmetrics.getFont(_FALLBACK_FONT).face.charWidths if _FALLBACK_FONT else {}
        runs: list[str] = []
        run: list[str] = []
        current = ''

        def flush() -> None:
            if not run:
                return
            body = html.escape(''.join(run), quote=False)
            if spaces:
                body = body.replace(' ', '&#160;')
            runs.append(f'<font name="{current}">{body}</font>')
            run.clear()

        for char in text:
            point = ord(char)
            if point in widths and point >= 32 and point != 127:
                selected, value = font, char
            elif point in fallback_widths and point >= 32 and point != 127:
                selected, value = str(_FALLBACK_FONT), char
            elif char in '\n\r\t':
                selected, value = font, ' '
            else:
                selected, value = font, f'[U+{point:04X}]'
                self.unsupported[point] = self.unsupported.get(point, 0) + 1
            if selected != current:
                flush()
                current = selected
            run.append(value)
        flush()
        return ''.join(runs)

    def inline(self, value: str) -> str:
        """Small, inert Markdown subset; source HTML is always printed literally."""
        tokens = re.split(
            r'(`[^`\n]+`|\*\*[^*\n]+\*\*|(?<![\w_])__[^_\n]+__(?![\w_])|!\[[^\]\n]*\]\([^\)\n]*\)|'
            r'\[[^\]\n]+\]\([^\)\n]*\)|\*[^*\n]+\*|(?<![\w_])_[^_\n]+_(?![\w_]))', value,
        )
        output: list[str] = []
        for token in tokens:
            if token.startswith('`') and token.endswith('`') and len(token) > 2:
                output.append(self.markup(token[1:-1], 'HyPrintMono'))
            elif token.startswith(('**', '__')) and token.endswith(token[:2]) and len(token) > 4:
                output.append(self.markup(token[2:-2], 'HyPrintBold'))
            elif token.startswith(('*', '_')) and token.endswith(token[0]) and len(token) > 2:
                output.append(self.markup(token[1:-1], 'HyPrintItalic'))
            elif token.startswith(('![', '[')) and (match := re.fullmatch(r'!?\[([^\]]*)\]\((.*)\)', token)):
                label, target = match.groups()
                # No ReportLab <link> tag: even local/file/javascript URLs are
                # plain text, and an image never triggers a fetch or file open.
                output.append(self.markup(('Image reference: ' if token.startswith('!') else '')
                                          + label + (f' ({target})' if target else '')))
            else:
                output.append(self.markup(token))
        return ''.join(output)


def _styles() -> dict[str, ParagraphStyle]:
    return {
        'body': ParagraphStyle('HyPrintBody', fontName='HyPrint', fontSize=9.2, leading=13.5,
                               textColor=_INK, spaceAfter=6, splitLongWords=1,
                               allowWidows=1, allowOrphans=1, wordWrap='CJK'),
        'meta': ParagraphStyle('HyPrintMeta', fontName='HyPrint', fontSize=7.8, leading=11,
                               textColor=_MUTED, spaceAfter=5, splitLongWords=1,
                               allowWidows=1, allowOrphans=1, wordWrap='CJK'),
        'heading': ParagraphStyle('HyPrintHeading', fontName='HyPrintBold', fontSize=10,
                                  leading=14, textColor=_ACCENT, spaceBefore=10,
                                  spaceAfter=4, keepWithNext=1, splitLongWords=1, wordWrap='CJK'),
        'markdown_heading': ParagraphStyle('HyPrintMarkdownHeading', fontName='HyPrintBold', fontSize=10,
                                           leading=14, textColor=_ACCENT, spaceBefore=10,
                                           spaceAfter=4, keepWithNext=0, splitLongWords=1, wordWrap='CJK'),
        'title': ParagraphStyle('HyPrintTitle', fontName='HyPrintBold', fontSize=17,
                                leading=22, textColor=_INK, spaceAfter=8,
                                splitLongWords=1, wordWrap='CJK'),
        'compact': ParagraphStyle('HyPrintCompact', fontName='HyPrint', fontSize=8.3,
                                  leading=12, textColor=_MUTED, backColor=colors.HexColor('#f2f6f5'),
                                  borderColor=_BORDER, borderWidth=.4, borderPadding=5,
                                  spaceBefore=5, spaceAfter=5, splitLongWords=1,
                                  allowWidows=1, allowOrphans=1, wordWrap='CJK'),
        'code': ParagraphStyle('HyPrintCode', fontName='HyPrintMono', fontSize=8,
                               leading=10.8, textColor=_INK, backColor=_CODE_BG,
                               leftIndent=6, rightIndent=6, spaceBefore=0,
                               spaceAfter=0, splitLongWords=1, allowWidows=1,
                               allowOrphans=1, wordWrap='CJK'),
        'cell': ParagraphStyle('HyPrintCell', fontName='HyPrint', fontSize=8,
                               leading=11.4, textColor=_INK, splitLongWords=1,
                               allowWidows=1, allowOrphans=1, wordWrap='CJK'),
    }


def _chunks(value: str):
    if not value:
        yield ''
    else:
        for start in range(0, len(value), _PARAGRAPH_CHARS):
            yield value[start:start + _PARAGRAPH_CHARS]


def _code_line(value: str, text: _Text, styles: dict[str, ParagraphStyle]):
    # Expand tabs incrementally, so a giant tab-heavy line does not allocate
    # several additional copies before the worker can check cancellation.
    buffer: list[str] = []
    column = 0
    for char in value.rstrip('\r'):
        if char == '\t':
            count = 4 - column % 4
            buffer.extend(' ' * count)
            column += count
        else:
            buffer.append(char)
            column += 1
        if len(buffer) >= _PARAGRAPH_CHARS:
            yield Paragraph(text.markup(''.join(buffer), 'HyPrintMono', spaces=True), styles['code'])
            buffer.clear()
    if buffer or not value:
        yield Paragraph(text.markup(''.join(buffer), 'HyPrintMono', spaces=True) or '&#160;', styles['code'])


def _code_lines(value: str, text: _Text, styles: dict[str, ParagraphStyle]):
    # A paragraph per logical line can wrap and split across pages; a single
    # enormous Preformatted/Table/KeepTogether block cannot.
    yield Spacer(1, 3)
    for line in value.split('\n'):
        yield from _code_line(line, text, styles)
    yield Spacer(1, 6)


def _cells(line: str) -> list[str]:
    line = line.strip()
    if line.startswith('|'):
        line = line[1:]
    if line.endswith('|') and not line.endswith('\\|'):
        line = line[:-1]
    output, part = [], []
    escaped, code = False, False
    for char in line:
        if escaped:
            if char not in {'|', '\\', '`'}:
                part.append('\\')
            part.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '`':
            code = not code
            part.append(char)
        elif char == '|' and not code:
            output.append(''.join(part).strip())
            part = []
        else:
            part.append(char)
    if escaped:
        part.append('\\')
    output.append(''.join(part).strip())
    return output


def _table(lines: list[str], text: _Text, styles: dict[str, ParagraphStyle]):
    rows = [_cells(line) for line in lines]
    columns = max((len(row) for row in rows), default=0)
    if not columns:
        return
    rows = [row + [''] * (columns - len(row)) for row in rows]
    if columns > 6 or any(len(cell) > _PARAGRAPH_CHARS for row in rows for cell in row):
        yield Paragraph('Wide or long table - each row is printed below.', styles['meta'])
        headers = rows[0]
        if len(rows) == 1:
            for column, header in enumerate(headers, 1):
                for chunk in _chunks(f'Column {column}: ' + header):
                    yield Paragraph(text.inline(chunk), styles['body'])
        for number, row in enumerate(rows[1:], 1):
            yield Paragraph(text.markup(f'Row {number}', 'HyPrintBold'), styles['meta'])
            for header, cell in zip(headers, row):
                for chunk in _chunks(header + ': ' + cell):
                    yield Paragraph(text.inline(chunk), styles['body'])
        return
    data = [[Paragraph(text.inline(cell), styles['cell']) for cell in row] for row in rows]
    table = LongTable(data, colWidths=[_WIDTH / columns] * columns, repeatRows=1,
                      hAlign='LEFT', splitByRow=1, splitInRow=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e8f1ef')),
        ('GRID', (0, 0), (-1, -1), .4, _BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    yield table
    yield Spacer(1, 7)


def _markdown(value: str, text: _Text, styles: dict[str, ParagraphStyle]):
    lines = value.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    index = 0
    while index < len(lines):
        line = lines[index]
        fence = re.match(r'^\s{0,3}(`{3,}|~{3,})(.*)$', line)
        if fence:
            marker = fence.group(1)
            yield Spacer(1, 3)
            index += 1
            while index < len(lines) and not re.match(r'^\s{0,3}' + re.escape(marker[0]) + '{' + str(len(marker)) + r',}\s*$', lines[index]):
                yield from _code_line(lines[index], text, styles)
                index += 1
            yield Spacer(1, 6)
            if index < len(lines):
                index += 1
            continue
        if (index + 1 < len(lines) and '|' in line
                and all(re.fullmatch(r':?-{3,}:?', cell.strip()) for cell in _cells(lines[index + 1]))
                and len(_cells(lines[index + 1])) > 1):
            table_lines = [line]
            index += 2
            while index < len(lines) and '|' in lines[index] and lines[index].strip():
                table_lines.append(lines[index])
                index += 1
            yield from _table(table_lines, text, styles)
            continue
        if not line.strip():
            yield Spacer(1, 4)
            index += 1
            continue
        heading = re.match(r'^\s{0,3}#{1,6}\s+(.*?)(?:\s+#+\s*)?$', line)
        if heading:
            for chunk in _chunks(heading.group(1)):
                yield Paragraph(text.markup(chunk, 'HyPrintBold'), styles['markdown_heading'])
        elif re.fullmatch(r'\s*(?:-{3,}|\*{3,}|_{3,})\s*', line):
            yield HRFlowable(width='100%', thickness=.4, color=_BORDER, spaceBefore=4, spaceAfter=6)
        else:
            # Keep authored line boundaries, lists and quotes. A long line is
            # still a splittable paragraph rather than a clipped horizontal row.
            bullet = re.match(r'^(\s*)([-+*]|\d+[.)])\s+(.*)$', line)
            if bullet:
                indent, label, body = bullet.groups()
                prefix = '- ' if label in {'-', '+', '*'} else label + ' '
                style = ParagraphStyle('HyPrintList', parent=styles['body'],
                                       leftIndent=min(48, 8 + len(indent) * 2.5), firstLineIndent=-7)
                for number, chunk in enumerate(_chunks(body)):
                    yield Paragraph((text.markup(prefix) if number == 0 else '') + text.inline(chunk), style)
            elif line.lstrip().startswith('>'):
                style = ParagraphStyle('HyPrintQuote', parent=styles['body'], leftIndent=12,
                                       textColor=_MUTED)
                for chunk in _chunks(line.lstrip()[1:].lstrip()):
                    yield Paragraph(text.inline(chunk), style)
            else:
                for chunk in _chunks(line):
                    yield Paragraph(text.inline(chunk), styles['body'])
        index += 1


class _PrintDocument(BaseDocTemplate):
    def __init__(self, filename: str, *, cancel: threading.Event | None, progress: Callable[[str], None], **kwargs):
        super().__init__(filename, pagesize=A4, leftMargin=_MARGIN, rightMargin=_MARGIN,
                         topMargin=51, bottomMargin=42, pageCompression=1, **kwargs)
        self.cancel = cancel
        self.progress = progress
        self.pages_written = 0
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height,
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id='chat')
        self.addPageTemplates(PageTemplate(id='chat', frames=[frame], onPage=self._page))

    def _page(self, canvas, _doc) -> None:
        _cancelled(self.cancel)
        self.pages_written = max(self.pages_written, self.page)
        if self.page == 1 or self.page % 10 == 0:
            self.progress(f'Formatting PDF - page {self.page}...')
        canvas.saveState()
        canvas.setStrokeColor(_BORDER)
        canvas.setLineWidth(.4)
        canvas.line(_MARGIN, 30, _PAGE_WIDTH - _MARGIN, 30)
        canvas.setFillColor(_MUTED)
        canvas.setFont('HyPrint', 7)
        canvas.drawString(_MARGIN, 19, 'HarnessyXO - Printable chat')
        canvas.drawRightString(_PAGE_WIDTH - _MARGIN, 19, f'Page {self.page}')
        canvas.restoreState()

    def afterFlowable(self, _flowable) -> None:
        _cancelled(self.cancel)


def render_print_pdf(snapshot, options, output: Path, *, cancel: threading.Event | None = None,
                     progress: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Render exactly the selected snapshot contents to a finished PDF file.

    The caller owns snapshot/job cleanup and atomic publication. A cancelled or
    failed render removes its incomplete output, never a previously published
    document. No inference, network connection or attachment file access occurs.
    """
    options.validate()
    _cancelled(cancel)
    _fonts()
    progress = progress or (lambda _message: None)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError('The PDF output path already exists; choose a new export destination.')
    fields = set(options.metadata)
    text, styles = _Text(), _styles()
    story: list[Any] = []
    title = str(snapshot.title) if 'title' in fields else 'Printable chat'
    for chunk in _chunks(title):
        story.append(Paragraph(text.markup(chunk, 'HyPrintBold'), styles['title']))
    if 'title' in fields and getattr(snapshot, 'workspace_name', ''):
        for chunk in _chunks(str(snapshot.workspace_name)):
            story.append(Paragraph(text.markup(chunk), styles['meta']))
    if 'timestamps' in fields:
        story.append(Paragraph(text.markup('Saved snapshot: ' + str(snapshot.captured_at)), styles['meta']))
    if getattr(snapshot, 'active', False):
        story.append(Paragraph('Saved messages only. Streaming text was not included.', styles['meta']))
    warning_insert = len(story)
    story.append(HRFlowable(width='100%', thickness=.6, color=_BORDER, spaceBefore=3, spaceAfter=8))
    section_count, selected_bytes = 0, 0
    try:
        for section in snapshot.sections(options, cancel=cancel, progress=progress):
            _cancelled(cancel)
            section_count += 1
            if section_count > _MAX_SECTIONS:
                raise ValueError('This PDF has too many sections. Choose a smaller prompt selection or message range.')
            body = str(section.body or '')
            selected_bytes += len(body.encode('utf-8'))
            if selected_bytes > _MAX_RENDER_TEXT:
                raise ValueError('The selected full text exceeds 64 MiB. Choose a smaller range or use One line for large results.')
            label = str(section.label)
            metadata = tuple(str(value) for value in section.metadata if str(value))
            if section.compact:
                parts = (metadata[0], label, *metadata[1:]) if 'timestamps' in fields and metadata else (label, *metadata)
                line = ' · '.join(parts)
                story.append(Paragraph(text.markup(line), styles['compact']))
            else:
                story.append(Paragraph(text.markup(label, 'HyPrintBold'), styles['heading']))
                if metadata:
                    story.append(Paragraph(text.markup(' · '.join(metadata)), styles['meta']))
                if section.code:
                    flowables = _code_lines(body, text, styles)
                else:
                    flowables = _markdown(body, text, styles)
                for flowable in flowables:
                    _cancelled(cancel)
                    if len(story) >= _MAX_FLOWABLES:
                        raise ValueError('This PDF has too many formatted lines. Choose a smaller message range or use One line for large results.')
                    story.append(flowable)
            if section_count % 100 == 0:
                progress(f'Preparing PDF - {section_count:,} sections...')
        if not section_count:
            story.append(Paragraph('No saved content matches these export choices.', styles['body']))
        warning_count = sum(text.unsupported.values())
        warnings: list[str] = []
        if warning_count:
            codes = ', '.join(f'U+{point:04X}' for point in sorted(text.unsupported)[:12])
            if len(text.unsupported) > 12:
                codes += ', ...'
            warning = (f'{warning_count:,} unsupported characters are printed as Unicode codes '
                       f'in square brackets ({codes}).')
            warnings.append(warning)
            story.insert(warning_insert, Paragraph(text.markup(warning), styles['meta']))
        _cancelled(cancel)
        doc = _PrintDocument(str(output), cancel=cancel, progress=progress,
                             title=title, author='HarnessyXO', subject='Printable chat export')
        doc.build(story)
        _cancelled(cancel)
        if not output.is_file() or output.stat().st_size < 5:
            raise RuntimeError('The PDF renderer did not produce a valid document.')
        with output.open('rb') as stream:
            if stream.read(5) != b'%PDF-':
                raise RuntimeError('The PDF renderer did not produce a valid document.')
        return {'pages': doc.pages_written, 'sections': section_count, 'bytes': output.stat().st_size,
                'warnings': warnings, 'unsupported_characters': warning_count}
    except BaseException:
        output.unlink(missing_ok=True)
        raise
