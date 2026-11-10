import argparse
from html import escape
import json
from pathlib import Path
import sys
import os
import tempfile
from . import __version__
from .core import MAX_BYTES, address_range, compare, parse, policy


def load(path, limit):
    path = Path(path)
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('input exceeds 128 MiB text limit')
    with path.open('rb') as stream:
        data = stream.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024:
        raise ValueError('input exceeds 128 MiB text limit')
    return parse(data.decode('ascii'), limit)


def render(report, fmt):
    encoded = json.dumps(report, indent=2, ensure_ascii=True)
    if fmt == 'json':
        return encoded + '\n'
    summary = report.get('after', report.get('image', {}))
    rows = report.get('changed_blocks', [])
    status = 'PASS' if not report['violations'] else 'POLICY FAILED'
    if fmt == 'markdown':
        lines = ['# Firmware image review', '', status, '', 'Image bytes: %s' % summary.get('bytes'),
                 '', '| Block address | Added | Removed | Modified |', '|---|---:|---:|---:|']
        lines += ['| 0x%08x | %d | %d | %d |' % (r['start'], r['added_bytes'], r['removed_bytes'], r['modified_bytes']) for r in rows]
        lines += ['', '```json', encoded, '```']
        return '\n'.join(lines) + '\n'
    table = ''.join('<tr><td>0x%08x</td><td>%d</td><td>%d</td><td>%d</td></tr>' %
                    (r['start'], r['added_bytes'], r['removed_bytes'], r['modified_bytes']) for r in rows)
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>Firmware image review</title>'
            '<style>body{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:1rem;background:#f4f7fb;color:#15243b}'
            'table{border-collapse:collapse;width:100%%;background:white}td,th{padding:12px;text-align:left;border-bottom:1px solid #dde3eb}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#fff;padding:20px}h1{color:#12627c}</style>'
            '<h1>Firmware image review</h1><p>%s · %s mapped bytes · %d changed blocks</p>'
            '<p>Address ranges are half-open. Sparse holes are not assumed to contain erased bytes. No device is accessed.</p>'
            '<table><tr><th>Block start</th><th>Added bytes</th><th>Removed bytes</th><th>Modified bytes</th></tr>%s</table>'
            '<h2>Evidence and policy results</h2><pre>%s</pre></html>') % (status, summary.get('bytes'), len(rows), table, escape(encoded))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Validate Intel HEX / S-record images and review changed flash blocks.')
    parser.add_argument('--version', action='version', version=__version__)
    subs = parser.add_subparsers(dest='command', required=True)
    for name in ('check', 'compare', 'demo'):
        p = subs.add_parser(name)
        if name == 'check':
            p.add_argument('image')
        elif name == 'compare':
            p.add_argument('before'); p.add_argument('after')
        p.add_argument('--output', type=Path)
        p.add_argument('--format', choices=('json', 'markdown', 'html'), default='html' if name == 'demo' else 'json')
        p.add_argument('--allow', action='append', default=[], metavar='START:END_EXCLUSIVE')
        p.add_argument('--forbid', action='append', default=[], metavar='START:END_EXCLUSIVE')
        p.add_argument('--max-image-bytes', type=int)
        p.add_argument('--max-input-bytes', type=int, default=MAX_BYTES)
        p.add_argument('--require-entrypoint', action='store_true')
        p.add_argument('--block-size', type=int, default=4096)
        p.add_argument('--fail-on-change', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.max_input_bytes < 1 or args.max_image_bytes is not None and args.max_image_bytes < 1:
            raise ValueError('byte limits must be positive')
        allowed = [address_range(r) for r in args.allow]
        forbidden = [address_range(r) for r in args.forbid]
        if args.command == 'demo':
            folder = Path(__file__).parent / 'fixtures'
            before = load(folder / 'before.hex', args.max_input_bytes)
            after = load(folder / 'after.hex', args.max_input_bytes)
            report = compare(before, after, args.block_size)
        elif args.command == 'compare':
            before = load(args.before, args.max_input_bytes)
            after = load(args.after, args.max_input_bytes)
            report = compare(before, after, args.block_size)
        else:
            after = load(args.image, args.max_input_bytes)
            report = {'image': after.summary()}
        report['violations'] = policy(after, allowed, forbidden, args.max_image_bytes, args.require_entrypoint)
        if args.fail_on_change and (report.get('changed_blocks') or report.get('entrypoint_changed')):
            report['violations'].append('image contents or entrypoint changed')
        result = render(report, args.format)
        if args.output:
            inputs = [getattr(args, key, None) for key in ('image', 'before', 'after')]
            if any(p and Path(p).resolve() == args.output.resolve() for p in inputs):
                raise ValueError('output must not overwrite an input image')
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=args.output.parent,
                                             delete=False) as stream:
                temporary = stream.name
                stream.write(result)
            try:
                os.replace(temporary, args.output)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        else:
            print(result, end='')
        return 1 if report['violations'] else 0
    except (OSError, ValueError, UnicodeError) as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 2

