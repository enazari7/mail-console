"""Server-rendered SVG charts (no JavaScript; colours come from CSS tokens)."""

from __future__ import annotations

import math
from html import escape
from typing import Callable

from markupsafe import Markup

SERIES = [("accepted", "Accepted"), ("deferred", "Deferred"), ("failed", "Failed")]


def nice_max(value: float) -> float:
    if value <= 0:
        return 4
    exp = 10 ** math.floor(math.log10(value))
    for m in (1, 2, 2.5, 5, 10):
        if value <= m * exp:
            nice = m * exp
            break
    return max(4, nice)


def _fmt_count(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M".replace(".0M", "M")
    if value >= 10_000:
        return f"{value / 1000:.0f}k"
    if value >= 1000:
        return f"{value / 1000:.1f}k".replace(".0k", "k")
    return f"{value:g}"


def stacked_bars(buckets: list[dict], label_for: Callable[[int], str], tick_for: Callable[[int], str],
                 *, width: int = 760, height: int = 240, title: str = "Delivery outcomes") -> Markup:
    """Stacked columns of accepted / deferred / failed counts per time bucket."""
    left, right, top, bottom = 44, 8, 10, 26
    plot_w, plot_h = width - left - right, height - top - bottom
    n = max(len(buckets), 1)
    totals = [sum(b[k] for k, _ in SERIES) for b in buckets]
    ymax = nice_max(max(totals, default=0))
    slot = plot_w / n
    bar_w = max(1.0, min(28.0, slot * 0.72))
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">']
    for i in range(5):
        v = ymax * i / 4
        y = top + plot_h - plot_h * i / 4
        parts.append(f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>')
        parts.append(f'<text class="axis" x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">{_fmt_count(v)}</text>')
    tick_every = max(1, math.ceil(n / 7))
    for i, b in enumerate(buckets):
        x0 = left + i * slot + (slot - bar_w) / 2
        y = top + plot_h
        segs = []
        for key, _ in SERIES:
            value = b[key]
            if not value:
                continue
            h = plot_h * value / ymax
            gap = 2 if segs else 0
            segs.append(f'<rect class="s-{key}" x="{x0:.1f}" y="{y - h + gap:.1f}" width="{bar_w:.1f}" '
                        f'height="{max(h - gap, 1):.1f}" rx="2"/>')
            y -= h
        tip = (f"{label_for(b['start'])}\n" +
               "\n".join(f"{name}: {b[key]}" for key, name in SERIES))
        parts.append(f'<g class="bar"><title>{escape(tip)}</title>'
                     f'<rect class="hit" x="{left + i * slot:.1f}" y="{top}" width="{slot:.1f}" height="{plot_h}"/>'
                     + "".join(segs) + "</g>")
        if i % tick_every == 0:
            parts.append(f'<text class="axis" x="{left + i * slot + slot / 2:.1f}" y="{height - 8}" '
                         f'text-anchor="middle">{escape(tick_for(b["start"]))}</text>')
    parts.append(f'<line class="baseline" x1="{left}" x2="{width - right}" y1="{top + plot_h}" y2="{top + plot_h}"/>')
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - every interpolated value is escaped


def domain_bars(domains: list[dict], *, width: int = 420) -> Markup:
    """Horizontal stacked bars: per destination domain outcome split."""
    if not domains:
        return Markup('<p class="empty">No recipient outcomes in this range.</p>')
    row_h, label_w, right = 30, 150, 44
    height = row_h * len(domains) + 4
    plot_w = width - label_w - right
    vmax = max(d["total"] for d in domains) or 1
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="Destination domains">']
    for i, d in enumerate(domains):
        y = 4 + i * row_h
        name = d["domain"] if len(d["domain"]) <= 22 else d["domain"][:21] + "…"
        parts.append(f'<g class="bar"><title>{escape(d["domain"])}\naccepted: {d["accepted"]}\n'
                     f'deferred: {d["deferred"]}\nfailed: {d["failed"]}\ntotal: {d["total"]}</title>')
        parts.append(f'<rect class="hit" x="0" y="{y}" width="{width}" height="{row_h - 4}"/>')
        parts.append(f'<text class="label" x="0" y="{y + 16}">{escape(name)}</text>')
        x = float(label_w)
        for key, _ in SERIES:
            value = d[key] or 0
            if not value:
                continue
            w = plot_w * value / vmax
            gap = 2 if x > label_w else 0
            parts.append(f'<rect class="s-{key}" x="{x + gap:.1f}" y="{y + 4}" width="{max(w - gap, 1):.1f}" '
                         f'height="{row_h - 12}" rx="2"/>')
            x += w
        parts.append(f'<text class="value" x="{x + 6:.1f}" y="{y + 16}">{d["total"]}</text></g>')
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - every interpolated value is escaped


def sparkline(points: list[dict], label_for: Callable[[int], str], *, width: int = 420, height: int = 64) -> Markup:
    """Single-series line for queue size over time."""
    if len(points) < 2:
        return Markup('<p class="empty">Not enough queue snapshots yet.</p>')
    t0, t1 = points[0]["ts"], points[-1]["ts"]
    span = max(t1 - t0, 1)
    vmax = max(max(p["total"] for p in points), 1)
    pad = 4
    coords = [(pad + (width - 2 * pad) * (p["ts"] - t0) / span,
               height - pad - (height - 2 * pad) * p["total"] / vmax) for p in points]
    path = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    last = points[-1]
    tip = f"{label_for(t0)} – {label_for(t1)}\nmax {vmax}, now {last['total']}"
    return Markup(  # noqa: S704 - every interpolated value is escaped or numeric
        f'<svg class="chart spark" viewBox="0 0 {width} {height}" role="img" aria-label="Queue size">'
        f'<title>{escape(tip)}</title>'
        f'<line class="grid" x1="{pad}" x2="{width - pad}" y1="{height - pad}" y2="{height - pad}"/>'
        f'<path class="line" d="{path}"/>'
        f'<circle class="dot" cx="{coords[-1][0]:.1f}" cy="{coords[-1][1]:.1f}" r="4"/></svg>'
    )
