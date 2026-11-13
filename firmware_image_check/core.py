"""Strict, sparse Intel HEX and Motorola S-record image inspection."""
from dataclasses import dataclass
import hashlib
import re

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 500000


@dataclass(frozen=True)
class Segment:
    start: int
    data: bytes

    @property
    def end(self):
        return self.start + len(self.data)


@dataclass(frozen=True)
class Image:
    format: str
    segments: tuple
    entry: object
    records: int

    @property
    def size(self):
        return sum(len(segment.data) for segment in self.segments)

    def summary(self):
        h = hashlib.sha256()
        for segment in self.segments:
            h.update(segment.start.to_bytes(8, 'big'))
            h.update(len(segment.data).to_bytes(8, 'big'))
            h.update(segment.data)
        return {'format': self.format, 'bytes': self.size, 'entrypoint': self.entry,
                'records': self.records, 'addressed_sha256': h.hexdigest(),
                'ranges': [{'start': s.start, 'end_exclusive': s.end} for s in self.segments]}


def _hex(text, line):
    if len(text) % 2 or not re.fullmatch(r'[0-9a-fA-F]+', text):
        raise ValueError('line %d: invalid hexadecimal record' % line)
    return bytes.fromhex(text)


def parse(text, max_bytes=MAX_BYTES):
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError('max_bytes must be positive')
    lines = [(i, line.strip()) for i, line in enumerate(text.splitlines(), 1) if line.strip()]
    if not lines or len(lines) > MAX_RECORDS:
        raise ValueError('empty image or record count exceeds %d' % MAX_RECORDS)
    kind = 'ihex' if lines[0][1].startswith(':') else 'srec'
    segments = []
    entry = None
    terminated = False
    base = 0
    total = 0
    data_records = 0
    s_data_type = None
    declared_count = None
    header_seen = False
    for number, line in lines:
        if terminated:
            raise ValueError('line %d: data after termination record' % number)
        if kind == 'ihex':
            if not line.startswith(':'):
                raise ValueError('line %d: mixed or invalid record format' % number)
            record = _hex(line[1:], number)
            if len(record) < 5 or len(record) != record[0] + 5:
                raise ValueError('line %d: byte count mismatch' % number)
            if sum(record) & 255:
                raise ValueError('line %d: checksum mismatch' % number)
            count, address, code = record[0], int.from_bytes(record[1:3], 'big'), record[3]
            payload = record[4:-1]
            if code == 0:
                if address + count > 0x10000:
                    raise ValueError('line %d: data crosses a 64 KiB record window' % number)
                absolute = base + address
                if absolute + count > 0x100000000:
                    raise ValueError('line %d: address exceeds uint32' % number)
                if count:
                    segments.append(Segment(absolute, payload))
                data_records += 1
                total += count
            elif code in (1, 2, 3, 4, 5):
                required = {1: 0, 2: 2, 3: 4, 4: 2, 5: 4}[code]
                if address or count != required:
                    raise ValueError('line %d: invalid control record shape' % number)
                if code == 1:
                    terminated = True
                elif code in (2, 4):
                    base = int.from_bytes(payload, 'big') << (4 if code == 2 else 16)
                else:
                    value = ((int.from_bytes(payload[:2], 'big') << 4) +
                             int.from_bytes(payload[2:], 'big')) if code == 3 else int.from_bytes(payload, 'big')
                    if entry is not None and entry != value:
                        raise ValueError('line %d: conflicting entrypoints' % number)
                    entry = value
            else:
                raise ValueError('line %d: unsupported Intel HEX record type' % number)
        else:
            if len(line) < 4 or line[0] != 'S' or line[1] not in '012356789':
                raise ValueError('line %d: unsupported S-record type' % number)
            code = int(line[1])
            record = _hex(line[2:], number)
            width = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2}[code]
            if len(record) < width + 2 or len(record) != record[0] + 1:
                raise ValueError('line %d: byte count mismatch' % number)
            if sum(record) & 255 != 255:
                raise ValueError('line %d: checksum mismatch' % number)
            address = int.from_bytes(record[1:1 + width], 'big')
            payload = record[1 + width:-1]
            if code in (1, 2, 3):
                if declared_count is not None:
                    raise ValueError('line %d: data after count record' % number)
                if s_data_type is not None and s_data_type != code:
                    raise ValueError('line %d: mixed S1/S2/S3 address widths' % number)
                s_data_type = code
                if address + len(payload) > 1 << (8 * width):
                    raise ValueError('line %d: record address overflow' % number)
                if payload:
                    segments.append(Segment(address, payload))
                total += len(payload)
                data_records += 1
            elif code == 0:
                if header_seen or data_records or address != 0:
                    raise ValueError('line %d: misplaced or invalid S0 header' % number)
                header_seen = True
            elif code in (5, 6):
                if payload or declared_count is not None or address != data_records:
                    raise ValueError('line %d: invalid data record count' % number)
                declared_count = address
            else:
                if payload or s_data_type is None or code != {1: 9, 2: 8, 3: 7}[s_data_type]:
                    raise ValueError('line %d: termination does not match data width' % number)
                entry = address
                terminated = True
        if total > max_bytes:
            raise ValueError('image data exceeds configured byte limit')
    if not terminated:
        raise ValueError('missing termination record')
    if not segments:
        raise ValueError('image contains no data')
    merged = []
    for segment in sorted(segments, key=lambda s: s.start):
        if merged and segment.start < merged[-1][0] + len(merged[-1][1]):
            raise ValueError('overlapping data records at 0x%x' % segment.start)
        if merged and segment.start == merged[-1][0] + len(merged[-1][1]):
            merged[-1][1].extend(segment.data)
        else:
            merged.append((segment.start, bytearray(segment.data)))
    return Image(kind, tuple(Segment(start, bytes(data)) for start, data in merged), entry, len(lines))


def address_range(value):
    def parse_piece(piece):
        if not isinstance(piece, str):
            raise ValueError
        piece = piece.strip()
        if re.fullmatch(r'[+-]?0[xX][0-9a-fA-F]+', piece):
            return int(piece, 16)
        if re.fullmatch(r'[+-]?[0-9]+', piece):
            return int(piece, 10)
        raise ValueError

    try:
        start, end = [parse_piece(piece) for piece in value.split(':')]
    except (ValueError, AttributeError):
        raise ValueError('range must be START:END_EXCLUSIVE (decimal or 0x hex)')
    if not 0 <= start < end <= 0x100000000:
        raise ValueError('range must satisfy 0 <= start < end <= 2**32')
    return start, end


def policy(image, allowed=(), forbidden=(), max_size=None, require_entry=False):
    violations = []
    # Merge ranges so adjacent permitted windows are treated as a union.
    permit = []
    for start, end in sorted(allowed):
        if permit and start <= permit[-1][1]:
            permit[-1] = (permit[-1][0], max(end, permit[-1][1]))
        else:
            permit.append((start, end))
    for segment in image.segments:
        if permit and not any(a <= segment.start and segment.end <= b for a, b in permit):
            violations.append('data range 0x%x:0x%x is outside allowed regions' % (segment.start, segment.end))
        for start, end in forbidden:
            if segment.start < end and segment.end > start:
                violations.append('data intersects forbidden range 0x%x:0x%x' % (start, end))
    if max_size is not None and image.size > max_size:
        violations.append('image size %d exceeds budget %d' % (image.size, max_size))
    if require_entry and (image.entry is None or not any(s.start <= image.entry < s.end for s in image.segments)):
        violations.append('entrypoint is missing or outside image data (no architecture-specific masking applied)')
    return violations


def _blocks(image, size):
    blocks = {}
    for segment in image.segments:
        offset = 0
        while offset < len(segment.data):
            address = segment.start + offset
            start = address // size * size
            part = min(size - (address - start), len(segment.data) - offset)
            if start not in blocks:
                if len(blocks) >= 100000:
                    raise ValueError('more than 100000 occupied blocks; use a larger block size')
                blocks[start] = []
            lo = address - start
            blocks[start].append((lo, segment.data[offset:offset + part]))
            offset += part
    return blocks


def compare(before, after, block_size=4096):
    if type(block_size) is not int or block_size < 1 or block_size > 1048576 or block_size & (block_size - 1):
        raise ValueError('block size must be a power of two in 1..1048576')
    old, new = _blocks(before, block_size), _blocks(after, block_size)
    changes = []
    for start in sorted(set(old) | set(new)):
        a, b = old.get(start, []), new.get(start, [])
        if a == b:
            continue
        overlap = modified = i = j = 0
        while i < len(a) and j < len(b):
            sa, da = a[i]; sb, db = b[j]
            ea, eb = sa + len(da), sb + len(db)
            lo, hi = max(sa, sb), min(ea, eb)
            if lo < hi:
                overlap += hi - lo
                modified += sum(x != y for x, y in zip(da[lo-sa:hi-sa], db[lo-sb:hi-sb]))
            if ea <= eb:
                i += 1
            if eb <= ea:
                j += 1
        added = sum(len(data) for _, data in b) - overlap
        removed = sum(len(data) for _, data in a) - overlap
        changes.append({'start': start, 'end_exclusive': start + block_size,
                        'added_bytes': added, 'removed_bytes': removed, 'modified_bytes': modified})
    return {'block_size': block_size, 'changed_blocks': changes,
            'entrypoint_changed': before.entry != after.entry,
            'before': before.summary(), 'after': after.summary()}
