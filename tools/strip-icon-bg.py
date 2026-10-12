#!/usr/bin/env python3
"""strip-icon-bg.py - remove a full-canvas background from traced module icons.

The module SVGs that came out of a background remover are potrace traces of the
whole image, background included. Their path starts with one subpath that
traces the entire canvas and then continues with the artwork knocked out of it:

    M0 2500 l0 -2500 2500 0 ... -2500z   m3442 1218 c...
    |______ full-canvas rectangle _____| |___ glyph ___|

GTK recolours every fill in a -symbolic icon to the theme colour, so that
rectangle is painted as a solid block around the glyph.

A leading subpath is removed only when it is closed, drawn with straight lines
only, and its bounding box covers the whole drawing - so artwork is never
deleted by pattern matching. Files left with no subpaths at all held nothing
but background; those are reported as needing re-tracing rather than silently
blanked.

Usage:
    tools/strip-icon-bg.py [--apply] [DIR]

Default is a dry run.
"""

import os
import re
import sys

NUM = re.compile(r'[-+]?(?:\d*\.\d+|\d+\.?)(?:[eE][-+]?\d+)?')
TOKEN = re.compile(r'([MmLlHhVvCcSsQqTtAaZz])([^MmLlHhVvCcSsQqTtAaZz]*)')


def subpaths(d):
    """Split a path 'd' into its subpaths (each starting at a moveto)."""
    parts, cur = [], []
    for tok in TOKEN.finditer(d):
        if tok.group(1) in 'Mm' and cur:
            parts.append(''.join(cur))
            cur = []
        cur.append(tok.group(0))
    if cur:
        parts.append(''.join(cur))
    return [p for p in parts if p.strip()]


def _walk_one(d, x, y):
    """Walk one subpath from carried-in point (x, y).

    Returns (box, x, y) with the point left at the subpath's end, so the next
    subpath continues from the right place.
    """
    start_x = start_y = x
    xs, ys = [], []

    for t in TOKEN.finditer(d):
        cmd, argstr = t.group(1), t.group(2)
        nums = [float(n) for n in NUM.findall(argstr)]
        if cmd in 'Mm':
            for i in range(0, len(nums) - 1, 2):
                if cmd == 'm':
                    x += nums[i]; y += nums[i + 1]
                else:
                    x, y = nums[i], nums[i + 1]
                xs.append(x); ys.append(y)
            start_x, start_y = x, y
        elif cmd in 'Ll':
            for i in range(0, len(nums) - 1, 2):
                if cmd == 'l':
                    x += nums[i]; y += nums[i + 1]
                else:
                    x, y = nums[i], nums[i + 1]
                xs.append(x); ys.append(y)
        elif cmd in 'Hh':
            for v in nums:
                x = x + v if cmd == 'h' else v
                xs.append(x); ys.append(y)
        elif cmd in 'Vv':
            for v in nums:
                y = y + v if cmd == 'v' else v
                xs.append(x); ys.append(y)
        elif cmd in 'Cc':
            for i in range(0, len(nums) - 5, 6):
                p = nums[i:i + 6]
                if cmd == 'c':
                    xs += [x + p[0], x + p[2], x + p[4]]
                    ys += [y + p[1], y + p[3], y + p[5]]
                    x += p[4]; y += p[5]
                else:
                    xs += [p[0], p[2], p[4]]
                    ys += [p[1], p[3], p[5]]
                    x, y = p[4], p[5]
        elif cmd in 'Zz':
            x, y = start_x, start_y
        else:
            # s/q/t/a are rare in this artwork; including their numbers can
            # only overestimate, which is safe for a containment test.
            for i in range(0, len(nums) - 1, 2):
                xs.append(nums[i]); ys.append(nums[i + 1])

    if not xs:
        return None, x, y
    return (min(xs), min(ys), max(xs), max(ys)), x, y


def walk(d):
    """Single pass over a whole path: (first_subpath_bbox, union_bbox).

    The pass must not restart per subpath. A relative moveto is relative to the
    current point, and after 'z' the current point is that subpath's start, so
    measuring a subpath in isolation puts it at the wrong origin - for these
    files that pushed the glyph outside the canvas and made the background
    rectangle look like it did not cover the drawing.
    """
    x = y = 0.0
    first_box = None
    union = None

    for idx, p in enumerate(subpaths(d)):
        box, x, y = _walk_one(p, x, y)
        if box is None:
            continue
        if idx == 0 or first_box is None:
            first_box = box
        union = box if union is None else (
            min(union[0], box[0]), min(union[1], box[1]),
            max(union[2], box[2]), max(union[3], box[3]))
    return first_box, union


def is_rect_like(path):
    """A traced background rectangle is closed and drawn with straight lines
    only; artwork almost always contains curves."""
    return (re.search(r'[cCsSqQaA]', path) is None
            and path.rstrip().endswith(('z', 'Z')))


def covers(first_box, union, tol=0.02):
    """True when the first subpath spans the full extent of the drawing."""
    if first_box is None or union is None:
        return False
    span = max(union[2] - union[0], union[3] - union[1])
    if span <= 0:
        return False
    t = span * tol
    return (first_box[0] <= union[0] + t and first_box[1] <= union[1] + t and
            first_box[2] >= union[2] - t and first_box[3] >= union[3] - t)


def process(path, apply_change):
    svg = open(path, encoding='utf-8', errors='replace').read()
    m = re.search(r'<path\b[^>]*\bd="([^"]*)"', svg, re.S)
    if not m:
        return 'no-path', 0

    d = m.group(1)
    parts = subpaths(d)
    first_box, union = walk(d)
    bg = is_rect_like(parts[0]) and covers(first_box, union) if parts else False

    if len(parts) < 2:
        return ('background-only' if bg else 'nothing-to-do'), len(parts)
    if not bg:
        return 'first-subpath-is-art', len(parts)

    if not apply_change:
        return 'would-strip', len(parts) - 1

    new_d = ' '.join(parts[1:])
    open(path, 'w', encoding='utf-8').write(svg[:m.start(1)] + new_d + svg[m.end(1):])
    return 'stripped', len(parts) - 1


def main():
    args = sys.argv[1:]
    apply_change = '--apply' in args
    rest = [a for a in args if not a.startswith('--')]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = rest[0] if rest else os.path.join(root, 'native/resources/icons/symbolic')

    files = sorted(f for f in os.listdir(target)
                   if f.startswith('wifisting-') and f.endswith('.svg'))
    print(f"{'applying to' if apply_change else 'dry run on'} {target}")
    print(f"{len(files)} wifisting icon(s)\n")

    tally = {}
    for f in files:
        status, left = process(os.path.join(target, f), apply_change)
        tally[status] = tally.get(status, 0) + 1
        if status in ('stripped', 'would-strip', 'background-only',
                      'first-subpath-is-art'):
            print(f"  {status:<22} {f}  ({left} subpath(es) left)")

    print()
    for k in sorted(tally):
        print(f"  {k:<22} {tally[k]}")
    if not apply_change:
        print("\ndry run - re-run with --apply to strip the backgrounds")


if __name__ == '__main__':
    main()
