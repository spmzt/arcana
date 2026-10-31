# The network map moved on a canvas

What a pointer move on the map costs, measured before anything was
changed, and what was done about it: the research's stage 4 ("links
and nodes in GL, moves during a drag that redraw only the canvas"),
with WebGPU beside WebGL 2.

## How it was measured

`pwa_test:pwa_map` and `pwa_test:pwa_mapgpu` (`moves_measure()`) wrap
`Module._arc_on_action` in the page and time it: the action and the
drawing after it (the C that builds the map's HTML, and morphdom's
patch of the DOM), which is everything a pointer move costs the page
apart from the browser's own layout and paint.  Forty moves of a
host, forty of the map (a pan), forty turns of the wheel, each waited
for over two animation frames; the mean, median and worst, and how
many changes the SVG saw meanwhile (a MutationObserver on it).  "A
whole redraw" is ten presses of the zoom buttons, which draw the whole
map: what every move of a drag cost before.

Sizes: the test's own lab (2 hosts, 1 link), and a fleet invented in
the browser, every host's agent answered by a `fetch` override in the
test: 40 hosts and 500 point-to-point links.  A thousand links (63
hosts) was tried first: the map does not even load within the case's
fifteen minutes, because every host is polled every five seconds and
each answer runs `links_build()` and draws the whole map again (about
half a second each at that size, so the page never rests).  That is
the next cost to take, and it is not a pointer's: see the end.

Headless Chromium 156 on the lab VM (FreeBSD 16-CURRENT, 4 CPUs, no
GPU: WebGL 2 and WebGPU through SwiftShader).  The numbers compare the
two paths; a desktop with a GPU is faster at both.

## Before: every move drew the whole map

| | 2 hosts | 40 hosts, 500 links |
|---|---|---|
| a move of a host | 2.0 ms, ~730 SVG changes for 39 moves | ~280 ms (median 293, worst 341) |
| a whole redraw (zoom buttons) | 1.7–2.9 ms | 225–280 ms |

At 500 links a drag ran at three or four frames a second.

## After

A host dragged: its own `<g>` follows the hand by its transform
(`data-follow` in bridge.js, no page drawn); the lines that move with
it are hidden in the SVG once, at the start, and drawn on the canvas
(`glmap_scene_*`, from `link_geom()`, the same geometry the SVG uses)
at each move; the map's HTML is drawn again once, when the hand lets
go.  A link bent: the same for that one line.  A pan, or a turn of the
wheel: the SVG and the canvas are moved as one by a CSS transform
(`arc_map_view`), and the map is drawn anew in the new view when the
hand lets go, or 150 ms after the wheel's last turn.

| WebGL 2 | 2 hosts | 40 hosts, 500 links |
|---|---|---|
| a move of a host | 0.1 ms, 1 SVG change a move, 1 line on the canvas | 0.1–0.2 ms, 1 SVG change a move, 25 lines on the canvas |
| a move of the map | 0.1 ms | 0.1 ms |
| a turn of the wheel | 0.1 ms | 0.1 ms |

About a thousand times less per move at 500 links: the drag keeps up
with the hand at any size the map loads at.  With Motion off nothing
animates: the canvas draws one frame per move of the hand and stops.
Without WebGL 2 or WebGPU `glmap_on()` is false and every move draws
the map as before; the SVG stays the only layer a pointer, a keyboard
or a screen reader uses, and picking stays the SVG's (`data-drop`,
`elementFromPoint`) on the CPU.

## WebGPU beside WebGL 2

glmap.c has a small backend interface (`struct backend`: open, draw,
close) over one scene kept in C: points (fuses, drop targets, probes,
the drawing line) and segments (the lines moving with the hand), both
drawn as instanced quads; WebGPU is asked for when `navigator.gpu`
exists (WGSL shaders, one render pipeline each, through emscripten's
emdawnwebgpu port and `webgpu.h`), else WebGL 2 through GLES 3, else
nothing.  A lost device or context is made again from the scene; a
device lost three times leaves the map to WebGL 2, on a fresh canvas
(a canvas that had a WebGPU context takes no other).

What it buys here: nothing that can be measured.  A frame is at most
16,384 points and 6,144 segments, uploaded and drawn in one call each;
both backends do it in well under a millisecond, and the per-move cost
is the C that turns the scene into instances, the same for both.  The
cost that remains (a whole map built as HTML on every data change) is
neither backend's.

What it costs:

(WebGPU is built only with `WITH_WEBGPU=yes`, the port's `WEBGPU`
option; without it WebGL 2 is the only backend and none of this applies.)

- Dawn's `emdawnwebgpu` package, v20260423.175430 (about 128 KB
  zipped, with emscripten 6.0.3), which emcc takes as a local port
  (`--use-port=<its emdawnwebgpu.port.py>`): `make depends` fetches
  the zip into `build/emdawnwebgpu` and unpacks it, or takes one copied
  there, so that the build itself needs no network; the port fetches
  the same zip as a distfile.
  `EMDAWN=emdawnwebgpu` has emcc fetch it from Dawn's releases instead;
- about 73 KB more JavaScript in `arcana.js` (227 KB to 300 KB) and a
  few KB of wasm;
- the device comes asynchronously: the first frames wait for it;
- in headless Chromium with `--enable-unsafe-webgpu
  --enable-features=Vulkan --use-angle=swiftshader` the device is had
  and draws, then is lost ("A valid external Instance reference no
  longer exists" until the instance was held, "Device was destroyed"
  since the device and adapter are too), again after each new
  device; `pwa_mapgpu` checks
  that the map falls back to WebGL 2 and the drag still goes by the
  canvas, and skips with that reason.  Whether a real GPU keeps the
  device is to be seen in a desktop browser.

No third-party library (sokol_gfx was the one candidate): raw GLES 3
and `webgpu.h` are each a few hundred lines here, and nothing measured
would be faster through it.

If WebGPU stays without a measured gain on real hardware, it is the
part to take out again: WebGL 2 alone does the whole of stage 4.

## Next

The cost left is not the pointer's: at a few hundred links each poll's
answer (every host, every five seconds) rebuilds the links and the
whole map's HTML.  Drawing again only when what a host said changed,
and the links and nodes themselves on the canvas with the SVG holding
only what is picked, labelled or focused, is what would take the map
to a thousand links.
