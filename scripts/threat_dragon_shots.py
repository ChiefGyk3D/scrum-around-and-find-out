# SPDX-License-Identifier: Apache-2.0
"""Open a Threat Dragon model in the hosted app (headless Chromium, 1920x1080) through the app's own Open/Import
flow and screenshot every view: the model page, each diagram (an overview and 100% tiles) and the report.

usage: python scripts/threat_dragon_shots.py docs/threat-model/safo.threat-dragon.json after [OUTDIR]
PNGs go to OUTDIR (default ./td-shots) as PREFIX-*.png. Needs network access to the hosted app and
`pip install playwright && playwright install chromium` in a separate venv (not a SAFO dependency).
"""

import json
import pathlib
import sys

from playwright.sync_api import sync_playwright

OUT = pathlib.Path(sys.argv[3] if len(sys.argv) > 3 else "td-shots")
OUT.mkdir(parents=True, exist_ok=True)
model, prefix = pathlib.Path(sys.argv[1]), sys.argv[2]
text = model.read_text(encoding="utf-8")
diagrams = json.loads(text)["detail"]["diagrams"]

BBOX = """() => { const r = document.querySelector('.x6-graph-svg-stage').getBoundingClientRect();
  const s = document.querySelector('.x6-graph-scroller');
  return {l: r.left + s.scrollLeft, t: r.top + s.scrollTop, w: r.width, h: r.height, x0: s.getBoundingClientRect().left,
          y0: s.getBoundingClientRect().top, sw: s.clientWidth, sh: s.clientHeight}; }"""

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1920, "height": 1080})
    warnings = []
    pg.on(
        "console",
        lambda m: warnings.append(m.text[:300]) if m.type in ("error", "warning") and "schema" in m.text else None,
    )
    pg.goto("https://www.threatdragon.com/", wait_until="networkidle")
    pg.get_by_text("Login to Local Session").click()
    pg.wait_for_timeout(800)
    pg.get_by_role("link", name="Open an existing threat model").click()
    pg.wait_for_timeout(800)
    pg.fill("#json-input", text)
    pg.click("#td-import-btn")
    pg.wait_for_timeout(2500)
    pg.screenshot(path=str(OUT / f"{prefix}-model.png"), full_page=True)
    for i, d in enumerate(diagrams):
        pg.locator(".card", has_text=d["title"]).first.click()
        pg.wait_for_timeout(5000)
        # tiles at 100%: scroll the graph scroller over the drawing
        bb = pg.evaluate(BBOX)
        print("diagram", i, d["title"], "drawing", bb)
        # find the drawing's own extent from the cells
        xs, ys = [], []
        for c in d["cells"]:
            if "position" in c:
                xs += [c["position"]["x"], c["position"]["x"] + c["size"]["width"]]
                ys += [c["position"]["y"], c["position"]["y"] + c["size"]["height"]]
        w, h = max(xs) - min(xs), max(ys) - min(ys)
        pg.evaluate("document.querySelector('.x6-graph-scroller').style.height = '760px'")
        tile = 0
        step_x, step_y = 1500, 640
        top = 0
        while top < h + 40:
            left = 0
            while left < w + 40:
                pg.evaluate(
                    "([l, t]) => { const s = document.querySelector('.x6-graph-scroller');"
                    " const g = document.querySelector('#graph-container');"
                    " s.scrollTo(l + parseFloat(g.style.left), t + parseFloat(g.style.top)); }",
                    [min(xs) + left - 40 + 0, min(ys) + top - 40],
                )
                pg.wait_for_timeout(500)
                pg.screenshot(path=str(OUT / f"{prefix}-diagram{i}-tile{tile}.png"))
                tile += 1
                left += step_x
            top += step_y
        # overview: zoom out, make the graph pane tall enough for the whole drawing, scroll the drawing into view
        for _ in range(2):
            pg.mouse.click(1597, 79)
            pg.wait_for_timeout(400)
        pg.add_style_tag(content=".x6-graph-scroller { height: 1000px !important; }")
        pg.wait_for_timeout(800)
        pg.evaluate("""() => { const s = document.querySelector('.x6-graph-scroller');
            let L = 1e9, T = 1e9;
            document.querySelectorAll('#graph-container [data-cell-id]').forEach(e => {
                const q = e.getBoundingClientRect();
                if (q.width > 0) { L = Math.min(L, q.left); T = Math.min(T, q.top); } });
            const r = {left: L, top: T};
            const sr = s.getBoundingClientRect();
            s.scrollTo(s.scrollLeft + r.left - sr.left - 20, s.scrollTop + r.top - sr.top - 20); }""")
        pg.wait_for_timeout(800)
        pg.screenshot(path=str(OUT / f"{prefix}-diagram{i}-overview.png"), full_page=True)
        pg.go_back()
        pg.wait_for_timeout(800)
    pg.evaluate("h => { location.hash = h; }", "#/local/" + "SAFO%20threat%20model" + "/report")
    pg.wait_for_timeout(3000)
    pg.screenshot(path=str(OUT / f"{prefix}-report.png"), full_page=True)
    print("schema warnings:", warnings)
    b.close()
