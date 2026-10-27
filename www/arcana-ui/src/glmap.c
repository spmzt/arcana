/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the network map shows moving, drawn by WebGL 2 under its SVG.
 * The SVG keeps everything a reader or a pointer needs (boxes, names,
 * links, labels, and its own dashes for the traffic, which read better
 * than points along a link); where WebGL 2 is not to be had, this layer
 * is not drawn.
 *
 * A host with a safe change waiting to be confirmed has a fuse round its
 * box: points that burn down as the time the agent gives it runs out,
 * amber, red for the last ten seconds.  It is the change's state, not an
 * effect, so it is drawn with motion off too.
 *
 * topo.c hands the links over each time it draws the map (glmap_begin,
 * glmap_link, glmap_fuse, glmap_end), in the map's own units with the
 * SVG's view box; the points move between draws on the browser's
 * animation frames, and the frames stop when nothing is drawn or the
 * canvas is gone (the page left the map).
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten/html5.h>
#include <GLES3/gl3.h>

#include "app.h"

#define	GL_LINKS	1024
#define	GL_POINTS_MAX	16384
#define	GL_KINDS	8
#define	GL_CANVAS	"#map-gl"
#define	GL_FUSES	64
#define	FUSE_DOTS	120		/* round a box */

struct gllink {
	float	x1, y1, cx, cy, x2, y2;	/* the curve, quadratic */
	float	t0, t1;			/* where it leaves each end's box */
	float	ab, ba;			/* bytes a second each way */
	float	w;			/* its wire's width */
	int	kind;
	bool	up;
};

/* A measured tunnel: its probes as its last sample saw them. */
struct glprobe {
	struct gllink	 c;		/* the curve, its ends */
	float		 delay, ipdv;	/* one way, ms */
	float		 loss;		/* the share lost, 0 to 1 */
};

/* A safe change's fuse, round a host's box. */
struct glfuse {
	float		 x, y, w, h;	/* the box: its middle and size */
	long long	 by;		/* undone then, in seconds of the epoch */
	float		 total;		/* the seconds it had */
};

static struct {
	EMSCRIPTEN_WEBGL_CONTEXT_HANDLE	 ctx;
	GLuint				 prog, vao, vbo;
	bool				 failed;	/* no WebGL 2 here */
	bool				 lost;
	bool				 running;	/* frames asked for */
	struct gllink			 l[GL_LINKS];
	int				 n;
	struct glfuse			 f[GL_FUSES];
	int				 nf;
	/* A line being drawn from a host: where from, where the pointer
	 * is, and the boxes it can be dropped on. */
	bool				 drafting;
	float				 dx1, dy1, dx2, dy2;
	struct glfuse			 t[GL_FUSES];
	int				 nt;
	struct glprobe			 p[GL_LINKS];
	int				 np;
	double				 vx, vy, vw, vh;	/* the view box */
	float				 rgb[GL_KINDS][3];
	float				 red[3];
	float				 buf[GL_POINTS_MAX * 7];
	int				 points;
	int				 cw, ch;	/* the canvas, in pixels */
} gl;

/* The layer's canvas, in the map's box under its SVG. */
void
glmap_html(struct html *h)
{

	if (!gl.failed)
		h_raw(h, "<canvas id=\"map-gl\" class=\"map-gl\" data-keep "
		    "aria-hidden=\"true\"></canvas>");
}

/* Whether the map's flows are this layer's: the SVG's dashes are not
 * drawn then. */
bool
glmap_on(void)
{

	return (gl.ctx > 0 && !gl.failed && !gl.lost);
}

static const char vs_src[] =
    "#version 300 es\n"
    "layout(location = 0) in vec2 pos;\n"
    "layout(location = 1) in float size;\n"
    "layout(location = 2) in vec4 col;\n"
    "out vec4 v_col;\n"
    "void main() {\n"
    "	gl_Position = vec4(pos, 0.0, 1.0);\n"
    "	gl_PointSize = size;\n"
    "	v_col = col;\n"
    "}\n";

/* A soft disc: a bright core and a glow that fades to its edge,
 * premultiplied. */
static const char fs_src[] =
    "#version 300 es\n"
    "precision mediump float;\n"
    "in vec4 v_col;\n"
    "out vec4 frag;\n"
    "void main() {\n"
    "	float r = length(gl_PointCoord - vec2(0.5)) * 2.0;\n"
    "	float glow = 1.0 - smoothstep(0.0, 1.0, r);\n"
    "	float core = 1.0 - smoothstep(0.28, 0.42, r);\n"
    "	float a = clamp(glow * 0.7 + core, 0.0, 1.0) * v_col.a;\n"
    "	frag = vec4(v_col.rgb * a, a);\n"
    "}\n";

static GLuint
shader(GLenum type, const char *src)
{
	GLuint	s;
	GLint	ok;

	s = glCreateShader(type);
	glShaderSource(s, 1, &src, NULL);
	glCompileShader(s);
	glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
	if (!ok) {
		glDeleteShader(s);
		return (0);
	}
	return (s);
}

/* Programs and buffers, made again after a context is restored. */
static bool
gl_build(void)
{
	GLuint	vs, fs;
	GLint	ok;

	if ((vs = shader(GL_VERTEX_SHADER, vs_src)) == 0 || (fs =
	    shader(GL_FRAGMENT_SHADER, fs_src)) == 0)
		return (false);
	gl.prog = glCreateProgram();
	glAttachShader(gl.prog, vs);
	glAttachShader(gl.prog, fs);
	glLinkProgram(gl.prog);
	glDeleteShader(vs);
	glDeleteShader(fs);
	glGetProgramiv(gl.prog, GL_LINK_STATUS, &ok);
	if (!ok)
		return (false);
	glGenVertexArrays(1, &gl.vao);
	glBindVertexArray(gl.vao);
	glGenBuffers(1, &gl.vbo);
	glBindBuffer(GL_ARRAY_BUFFER, gl.vbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(gl.buf), NULL, GL_STREAM_DRAW);
	glEnableVertexAttribArray(0);
	glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 7 * sizeof(float),
	    (void *)0);
	glEnableVertexAttribArray(1);
	glVertexAttribPointer(1, 1, GL_FLOAT, GL_FALSE, 7 * sizeof(float),
	    (void *)(2 * sizeof(float)));
	glEnableVertexAttribArray(2);
	glVertexAttribPointer(2, 4, GL_FLOAT, GL_FALSE, 7 * sizeof(float),
	    (void *)(3 * sizeof(float)));
	glEnable(GL_BLEND);
	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
	return (true);
}

static bool
on_lost(int type, const void *reserved, void *data)
{

	gl.lost = true;
	return (true);
}

static bool
on_restored(int type, const void *reserved, void *data)
{

	emscripten_webgl_make_context_current(gl.ctx);
	gl.lost = !gl_build();
	return (true);
}

/* A context on a canvas the page has just made. */
static void
gl_open(void)
{
	EmscriptenWebGLContextAttributes	a;

	if (gl.ctx > 0)
		emscripten_webgl_destroy_context(gl.ctx);
	emscripten_webgl_init_context_attributes(&a);
	a.majorVersion = 2;
	a.minorVersion = 0;
	a.alpha = true;
	a.premultipliedAlpha = true;
	a.antialias = false;
	a.depth = false;
	a.stencil = false;
	a.powerPreference = EM_WEBGL_POWER_PREFERENCE_LOW_POWER;
	gl.ctx = emscripten_webgl_create_context(GL_CANVAS, &a);
	gl.lost = false;
	gl.cw = gl.ch = 0;
	if (gl.ctx <= 0 || emscripten_webgl_make_context_current(gl.ctx) !=
	    EMSCRIPTEN_RESULT_SUCCESS || !gl_build()) {
		/* Not here: the SVG's own dashes, from the next draw on. */
		gl.failed = true;
		gl.ctx = 0;
		arc_gl_report(0, 0, 0, 0);
		render();
		return;
	}
	emscripten_set_webglcontextlost_callback(GL_CANVAS, NULL, false,
	    on_lost);
	emscripten_set_webglcontextrestored_callback(GL_CANVAS, NULL, false,
	    on_restored);
	/* The SVG's dashes give way to this layer. */
	render();
}

/* The colours the theme gives the links' kinds, read as it is now. */
static void
colours(void)
{
	static const char *const vars[GL_KINDS] = { "--violet", "--teal",
	    "--blue", "--magenta", "--amber", "--dim", "--cyan", "--cyan" };
	int	i, c;

	for (i = 0; i < GL_KINDS; i++) {
		if ((c = arc_css_rgb(vars[i])) < 0)
			c = 0x22d3ee;
		gl.rgb[i][0] = (float)((c >> 16) & 0xff) / 255.0f;
		gl.rgb[i][1] = (float)((c >> 8) & 0xff) / 255.0f;
		gl.rgb[i][2] = (float)(c & 0xff) / 255.0f;
	}
	if ((c = arc_css_rgb("--red")) < 0)
		c = 0xf05d5e;
	gl.red[0] = (float)((c >> 16) & 0xff) / 255.0f;
	gl.red[1] = (float)((c >> 8) & 0xff) / 255.0f;
	gl.red[2] = (float)(c & 0xff) / 255.0f;
}

void
glmap_begin(double vx, double vy, double vw, double vh)
{

	gl.vx = vx;
	gl.vy = vy;
	gl.vw = vw;
	gl.vh = vh;
	gl.n = gl.nf = gl.nt = gl.np = 0;
	gl.drafting = false;
}

/* A line being drawn, from a host's port to the pointer. */
void
glmap_draft(double x1, double y1, double x2, double y2)
{

	gl.drafting = true;
	gl.dx1 = (float)x1;
	gl.dy1 = (float)y1;
	gl.dx2 = (float)x2;
	gl.dy2 = (float)y2;
}

/* A box the line can be dropped on, x and y its middle. */
void
glmap_target(double x, double y, double w, double h)
{
	struct glfuse	*t;

	if (gl.nt == GL_FUSES)
		return;
	t = &gl.t[gl.nt++];
	memset(t, 0, sizeof(*t));
	t->x = (float)x;
	t->y = (float)y;
	t->w = (float)w;
	t->h = (float)h;
}

/* A host's box, x and y its middle, with a safe change undone at by
 * (seconds of the epoch) unless confirmed; total, the seconds it had. */
void
glmap_fuse(double x, double y, double w, double h, long long by,
    double total)
{
	struct glfuse	*f;

	if (gl.nf == GL_FUSES)
		return;
	f = &gl.f[gl.nf++];
	f->x = (float)x;
	f->y = (float)y;
	f->w = (float)w;
	f->h = (float)h;
	f->by = by;
	f->total = (float)(total > 1 ? total : 1);
}

void
glmap_link(double x1, double y1, double x2, double y2, double bend,
    double t0, double t1, double ab, double ba, double w, int kind, bool up)
{
	struct gllink	*l;
	double		 dx, dy, len;

	if (gl.n == GL_LINKS)
		return;
	l = &gl.l[gl.n++];
	dx = x2 - x1;
	dy = y2 - y1;
	len = sqrt(dx * dx + dy * dy);
	if (len < 1)
		len = 1;
	/* The control point as topo.c's curve() has it. */
	l->x1 = (float)x1;
	l->y1 = (float)y1;
	l->x2 = (float)x2;
	l->y2 = (float)y2;
	l->cx = (float)((x1 + x2) / 2 - dy / len * bend);
	l->cy = (float)((y1 + y2) / 2 + dx / len * bend);
	l->t0 = (float)t0;
	l->t1 = (float)t1;
	l->ab = (float)ab;
	l->ba = (float)ba;
	l->w = (float)w;
	l->kind = kind >= 0 && kind < GL_KINDS ? kind : GL_KINDS - 1;
	l->up = up;
}

/* A tunnel measured: its curve as glmap_link's, and its last sample. */
void
glmap_probe(double x1, double y1, double x2, double y2, double bend,
    double t0, double t1, double delay, double ipdv, double loss)
{
	struct glprobe	*p;
	double		 dx, dy, len;

	if (gl.np == GL_LINKS)
		return;
	p = &gl.p[gl.np++];
	memset(p, 0, sizeof(*p));
	dx = x2 - x1;
	dy = y2 - y1;
	len = sqrt(dx * dx + dy * dy);
	if (len < 1)
		len = 1;
	p->c.x1 = (float)x1;
	p->c.y1 = (float)y1;
	p->c.x2 = (float)x2;
	p->c.y2 = (float)y2;
	p->c.cx = (float)((x1 + x2) / 2 - dy / len * bend);
	p->c.cy = (float)((y1 + y2) / 2 + dx / len * bend);
	p->c.t0 = (float)t0;
	p->c.t1 = (float)t1;
	p->delay = (float)(delay > 0 ? delay : 0);
	p->ipdv = (float)(ipdv > 0 ? ipdv : 0);
	p->loss = (float)(loss < 0 ? 0 : loss > 1 ? 1 : loss);
}

static bool frame(double now, void *data);

void
glmap_end(void)
{

	colours();
	if (!gl.running && !gl.failed) {
		gl.running = true;
		emscripten_request_animation_frame_loop(frame, NULL);
	}
}

/* A point of the curve at t, and the unit normal there. */
static void
at(const struct gllink *l, float t, float *x, float *y, float *nx, float *ny)
{
	float	u, tx, ty, d;

	u = 1 - t;
	*x = u * u * l->x1 + 2 * u * t * l->cx + t * t * l->x2;
	*y = u * u * l->y1 + 2 * u * t * l->cy + t * t * l->y2;
	tx = 2 * u * (l->cx - l->x1) + 2 * t * (l->x2 - l->cx);
	ty = 2 * u * (l->cy - l->y1) + 2 * t * (l->y2 - l->cy);
	d = sqrtf(tx * tx + ty * ty);
	if (d < 1e-3f)
		d = 1e-3f;
	*nx = -ty / d;
	*ny = tx / d;
}

static void
point(float x, float y, float size, const float *rgb, float a)
{
	float	*p;
	double	 s, ox, oy;

	if (gl.points == GL_POINTS_MAX)
		return;
	/* The SVG's view box, met in the middle (xMidYMid meet). */
	s = fmin(gl.cw / gl.vw, gl.ch / gl.vh);
	ox = (gl.cw - gl.vw * s) / 2;
	oy = (gl.ch - gl.vh * s) / 2;
	p = &gl.buf[gl.points++ * 7];
	p[0] = (float)((ox + (x - gl.vx) * s) / gl.cw * 2 - 1);
	p[1] = (float)(1 - (oy + (y - gl.vy) * s) / gl.ch * 2);
	p[2] = size;
	p[3] = rgb[0];
	p[4] = rgb[1];
	p[5] = rgb[2];
	p[6] = a;
}

/*
 * A fuse: dots round the box, a little outside it, from the middle of
 * its top clockwise; those of the time left lit, the one burning bright.
 */
static void
fuse(const struct glfuse *f, double epoch, float dpr, float scale)
{
	static const float	 dark[3] = { 0.5f, 0.55f, 0.6f };
	const float		*rgb;
	float			 amber[3], w, h, p, d, x, y, left, frac, size;
	int			 i, lit, c;

	left = (float)((double)f->by - epoch);
	if (left <= 0)
		return;
	frac = fminf(1, left / f->total);
	if (left <= 10)
		rgb = gl.red;
	else {
		if ((c = arc_css_rgb("--amber")) < 0)
			c = 0xf5b041;
		amber[0] = (float)((c >> 16) & 0xff) / 255.0f;
		amber[1] = (float)((c >> 8) & 0xff) / 255.0f;
		amber[2] = (float)(c & 0xff) / 255.0f;
		rgb = amber;
	}
	w = f->w + 12;
	h = f->h + 12;
	p = 2 * (w + h);
	lit = (int)(frac * FUSE_DOTS + 0.5f);
	size = 5.5f * dpr * fminf(1.6f, fmaxf(0.7f, scale));
	for (i = 0; i < FUSE_DOTS; i++) {
		/* Along the outline: top from its middle, right, bottom,
		 * left, top again. */
		d = fmodf(w / 2 + p * (float)i / FUSE_DOTS, p);
		if (d < w) {
			x = f->x - w / 2 + d;
			y = f->y - h / 2;
		} else if (d < w + h) {
			x = f->x + w / 2;
			y = f->y - h / 2 + (d - w);
		} else if (d < 2 * w + h) {
			x = f->x + w / 2 - (d - w - h);
			y = f->y + h / 2;
		} else {
			x = f->x - w / 2;
			y = f->y + h / 2 - (d - 2 * w - h);
		}
		if (i < lit)
			point(x, y, i == lit - 1 ? size * 2.2f : size, rgb,
			    i == lit - 1 ? 1.0f : 0.85f);
		else
			point(x, y, size * 0.6f, dark, 0.25f);
	}
}

/*
 * A box a line can be dropped on: its outline in dots that breathe, a
 * wave going round it, cyan.
 */
static void
target(const struct glfuse *f, double secs, float dpr, float scale)
{
	float	w, h, p, d, x, y, size, a;
	int	i, n;

	w = f->w + 12;
	h = f->h + 12;
	p = 2 * (w + h);
	n = 72;
	size = 5.0f * dpr * fminf(1.6f, fmaxf(0.7f, scale));
	for (i = 0; i < n; i++) {
		d = p * (float)i / (float)n;
		if (d < w) {
			x = f->x - w / 2 + d;
			y = f->y - h / 2;
		} else if (d < w + h) {
			x = f->x + w / 2;
			y = f->y - h / 2 + (d - w);
		} else if (d < 2 * w + h) {
			x = f->x + w / 2 - (d - w - h);
			y = f->y + h / 2;
		} else {
			x = f->x - w / 2;
			y = f->y + h / 2 - (d - 2 * w - h);
		}
		a = 0.35f + 0.55f * powf(0.5f + 0.5f * sinf((float)(secs * 4.0) -
		    (float)i * 6.2832f / (float)n * 2), 3);
		point(x, y, size, gl.rgb[6], a);
	}
}

/* The line being drawn: points rushing from the host to the pointer. */
static void
draft(double secs, float dpr, float scale)
{
	float	dx, dy, len, t, size;
	int	i, n;

	dx = gl.dx2 - gl.dx1;
	dy = gl.dy2 - gl.dy1;
	len = sqrtf(dx * dx + dy * dy);
	if (len < 4)
		return;
	n = (int)(len / 14);
	if (n < 2)
		n = 2;
	if (n > 120)
		n = 120;
	size = 7.0f * dpr * fminf(1.6f, fmaxf(0.7f, scale));
	for (i = 0; i < n; i++) {
		t = fmodf((float)(secs * 160.0) / len + (float)i / (float)n,
		    1.0f);
		point(gl.dx1 + dx * t, gl.dy1 + dy * t, size * (0.6f + 0.4f * t),
		    gl.rgb[6], 0.4f + 0.6f * t);
	}
}

/* A number of 0 to 1 that stays the same for a packet's n and salt. */
static float
hash01(unsigned int n, unsigned int salt)
{
	unsigned int	x;

	x = n * 2654435761u ^ salt * 2246822519u;
	x ^= x >> 15;
	x *= 2246822519u;
	x ^= x >> 13;
	return ((float)(x & 0xffffff) / (float)0x1000000);
}

/*
 * A measured tunnel's probes, both ways, on its wire: one sent every
 * PROBE_EVERY seconds, crossing in a time that grows with the delay
 * measured (a millisecond about half a second, a hundred about two),
 * sent early or late by up to the variation's share of the delay, and
 * lost, at the share measured: it fades out where it goes, without a
 * colour of its own (a red flash read as a mark in a random place); the
 * loss in numbers is the tunnel's label's.
 */
#define	PROBE_EVERY	0.55
static void
probes(const struct glprobe *p, int which, double secs, float dpr,
    float scale)
{
	static const float	 white[3] = { 0.93f, 0.97f, 1.0f };
	const struct gllink	*l;
	double			 cross, start, age;
	float			 t, x, y, nx, ny, cut, jit, size, f;
	long			 i, first, last;
	int			 dir;

	l = &p->c;
	cross = 0.35 + 0.9 * log10(1.0 + p->delay);
	jit = p->delay > 0 ? fminf(0.45f, p->ipdv / p->delay) : 0;
	size = 6.5f * dpr * fminf(1.6f, fmaxf(0.7f, scale));
	for (dir = 0; dir < 2; dir++) {
		last = (long)(secs / PROBE_EVERY) + 1;
		first = (long)((secs - cross - 1.0) / PROBE_EVERY) - 1;
		for (i = first; i <= last; i++) {
			unsigned int	n = (unsigned int)i * 2 + (unsigned int)dir;

			start = i * PROBE_EVERY + (hash01(n, (unsigned int)which) -
			    0.5f) * jit * PROBE_EVERY * 2;
			age = secs - start;
			if (age < 0)
				continue;
			t = (float)(age / cross);
			f = -1;
			if (hash01(n, (unsigned int)which + 7919u) < p->loss) {
				/* Lost: it fades out where it went, within the
				 * tunnel. */
				cut = 0.15f + 0.7f * hash01(n, (unsigned int)which +
				    104729u);
				if (t > cut) {
					f = (t - cut) * (float)cross / 0.35f;
					if (f > 1)
						continue;
					t = cut;
				}
			} else if (t > 1)
				/* Arrived: gone at the far end. */
				continue;
			if (dir == 1)
				t = 1 - t;
			t = l->t0 + t * (l->t1 - l->t0);
			at(l, t, &x, &y, &nx, &ny);
			if (f >= 0)
				point(x, y, size, white, 0.95f * (1 - f));
			else
				point(x, y, size, white, 0.95f);
		}
	}
}

static bool
frame(double now, void *data)
{
	const struct gllink	*l;
	double			 css_w, css_h, secs, s;
	float			 dpr;
	int			 state, i, w, h, flows;

	state = arc_gl_probe();
	if ((state & 1) == 0 || !app.visible) {
		/* The canvas is gone, or the page hidden: no frames until
		 * the map is drawn again. */
		gl.running = false;
		return (false);
	}
	if ((state & 2) != 0)
		gl_open();
	if (gl.failed || gl.ctx <= 0 || gl.lost)
		return (!gl.failed);
	emscripten_webgl_make_context_current(gl.ctx);
	dpr = (float)fmin(emscripten_get_device_pixel_ratio(), 2.0);
	if (emscripten_get_element_css_size(GL_CANVAS, &css_w, &css_h) !=
	    EMSCRIPTEN_RESULT_SUCCESS)
		return (true);
	w = (int)(css_w * dpr);
	h = (int)(css_h * dpr);
	if (w < 1 || h < 1)
		return (true);
	if (w != gl.cw || h != gl.ch) {
		emscripten_set_canvas_element_size(GL_CANVAS, w, h);
		gl.cw = w;
		gl.ch = h;
	}
	glViewport(0, 0, w, h);
	glClearColor(0, 0, 0, 0);
	glClear(GL_COLOR_BUFFER_BIT);
	gl.points = 0;
	flows = 0;
	s = fmin(gl.cw / gl.vw, gl.ch / gl.vh) / dpr;
	/* The safe changes waiting, whatever the motion. */
	for (i = 0; i < gl.nf; i++)
		fuse(&gl.f[i], arc_now() / 1000.0, dpr, (float)s);
	/* A line being drawn, and where it can go: the SVG's dashed line
	 * and lit boxes say as much without WebGL. */
	if (gl.drafting && app.fx && (state & 4) == 0) {
		draft(now / 1000.0, dpr, (float)s);
		for (i = 0; i < gl.nt; i++)
			target(&gl.t[i], now / 1000.0, dpr, (float)s);
	}
	/* The traffic: an effect, not drawn with effects off or motion
	 * not wanted (a change of either draws the map again). */
	secs = now / 1000.0;
	for (i = 0; app.fx && (state & 4) == 0 && i < gl.n; i++) {
		l = &gl.l[i];
		/* Its traffic is the SVG's dashes, which read better than
		 * points along it, and a link down is the SVG's to show:
		 * a mark at its middle was taken for one in a random place
		 * (the middle can be behind another host). */
		if (l->ab >= 1 || l->ba >= 1)
			flows++;
	}
	for (i = 0; app.fx && (state & 4) == 0 && i < gl.np; i++)
		probes(&gl.p[i], i, secs, dpr, (float)s);
	if (gl.points > 0) {
		glUseProgram(gl.prog);
		glBindVertexArray(gl.vao);
		glBindBuffer(GL_ARRAY_BUFFER, gl.vbo);
		glBufferSubData(GL_ARRAY_BUFFER, 0, (GLsizeiptr)gl.points * 7 *
		    sizeof(float), gl.buf);
		glDrawArrays(GL_POINTS, 0, gl.points);
	}
	arc_gl_report(1, gl.points, flows, gl.np);
	/* Nothing moves: the frames rest until the next draw. */
	if (gl.points == 0) {
		gl.running = false;
		return (false);
	}
	return (true);
}
