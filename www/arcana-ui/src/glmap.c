/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the network map shows moving, drawn on a canvas under its SVG.
 * The SVG keeps everything a reader or a pointer needs (boxes, names,
 * links, labels, and its own dashes for the traffic, which read better
 * than points along a link); where neither WebGPU nor WebGL 2 is to be
 * had, this layer is not drawn.
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
 *
 * While a host is dragged, or a link bent, the lines that move with the
 * hand are this layer's (glmap_scene_begin, glmap_scene_link,
 * glmap_scene_end): the SVG keeps its own hidden until the hand lets
 * go, and a move of the pointer draws the canvas alone, not the map's
 * HTML again (docs/notes/webgl-map.md has the numbers).  They are
 * drawn once per move, whatever the motion setting: a drag is the
 * hand's, not an effect.
 *
 * The scene lives here, in C: a frame turns it into plain instances
 * (points: a place, a size, a colour; segments: two ends, a half width,
 * a colour) and hands them to a backend, WebGPU through webgpu.h when
 * the browser has it and gives a device, else WebGL 2 through GLES 3.
 * Either is rebuilt from the scene when its device or context is lost.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten/html5.h>
#include <GLES3/gl3.h>
#include <webgpu/webgpu.h>

#include "app.h"

#define	GL_LINKS	1024
#define	GL_POINTS_MAX	16384
#define	GL_KINDS	8
#define	GL_CANVAS	"#map-gl"
#define	GL_FUSES	64
#define	FUSE_DOTS	120		/* round a box */
#define	GL_WIRES	256		/* the lines that move with the hand */
#define	WIRE_SEGS	24		/* a curve, in straight pieces */
#define	GL_SEGS_MAX	(GL_WIRES * WIRE_SEGS)
#define	PT_FLOATS	7		/* x, y (clip), size (px), r, g, b, a */
#define	SEG_FLOATS	9		/* x0, y0, x1, y1, half width (px), rgba */

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

/* A line that moves with the hand: the curve, as glmap_link has it. */
struct glwire {
	float	x1, y1, cx, cy, x2, y2;
	float	w;			/* its wire's width, the map's units */
	int	kind;
	bool	up, dim;
};

/*
 * What draws a frame: a device or a context on the canvas, pipelines,
 * buffers.  open says whether it is there: 1 and the frame can be
 * drawn, 0 not yet (a device asked for), -1 not on this browser.
 */
struct backend {
	const char	*name;
	int		 id;		/* as arc_gl_report says it */
	int		(*open)(void);
	bool		(*draw)(int, int, const float *, int, const float *,
			    int);
	void		(*close)(void);
};

static struct {
	const struct backend		*be;
	bool				 opened;
	bool				 failed;	/* no backend here */
	bool				 lost;		/* its device, context */
	int				 fails;		/* frames it would not draw */
	int				 opens;		/* backends opened, in all */
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
	struct glwire			 s[GL_WIRES];
	int				 ns;
	double				 vx, vy, vw, vh;	/* the view box */
	float				 rgb[GL_KINDS][3];
	float				 red[3];
	float				 buf[GL_POINTS_MAX * PT_FLOATS];
	int				 points;
	float				 sbuf[GL_SEGS_MAX * SEG_FLOATS];
	int				 segs;
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

	return (gl.opened && !gl.failed && !gl.lost);
}

/*
 * WebGL 2.  Points are GL_POINTS with a soft disc of a shader; a
 * segment is a quad of six corners the vertex shader makes from its
 * instance, as WebGPU's is.
 */
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

static const char svs_src[] =
    "#version 300 es\n"
    "layout(location = 0) in vec2 a;\n"
    "layout(location = 1) in vec2 b;\n"
    "layout(location = 2) in float hw;\n"
    "layout(location = 3) in vec4 col;\n"
    "uniform vec2 u_size;\n"
    "out vec4 v_col;\n"
    "void main() {\n"
    "	vec2 c[6] = vec2[](vec2(0.0, -1.0), vec2(1.0, -1.0), vec2(0.0, 1.0),\n"
    "	    vec2(1.0, -1.0), vec2(1.0, 1.0), vec2(0.0, 1.0));\n"
    "	vec2 k = c[gl_VertexID];\n"
    "	vec2 d = b - a;\n"
    "	float l = max(length(d), 0.001);\n"
    "	vec2 n = vec2(-d.y, d.x) / l;\n"
    "	vec2 p = a + d * k.x + n * k.y * hw;\n"
    "	gl_Position = vec4(p.x / u_size.x * 2.0 - 1.0,\n"
    "	    1.0 - p.y / u_size.y * 2.0, 0.0, 1.0);\n"
    "	v_col = col;\n"
    "}\n";

static const char sfs_src[] =
    "#version 300 es\n"
    "precision mediump float;\n"
    "in vec4 v_col;\n"
    "out vec4 frag;\n"
    "void main() {\n"
    "	frag = vec4(v_col.rgb * v_col.a, v_col.a);\n"
    "}\n";

static struct {
	EMSCRIPTEN_WEBGL_CONTEXT_HANDLE	 ctx;
	GLuint				 pprog, pvao, pvbo;
	GLuint				 sprog, svao, svbo;
	GLint				 ssize;
} wgl;

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

/* A program of two shaders, linked; 0 when one would not. */
static GLuint
program(const char *vsrc, const char *fsrc)
{
	GLuint	vs, fs, prog;
	GLint	ok;

	if ((vs = shader(GL_VERTEX_SHADER, vsrc)) == 0 || (fs =
	    shader(GL_FRAGMENT_SHADER, fsrc)) == 0)
		return (0);
	prog = glCreateProgram();
	glAttachShader(prog, vs);
	glAttachShader(prog, fs);
	glLinkProgram(prog);
	glDeleteShader(vs);
	glDeleteShader(fs);
	glGetProgramiv(prog, GL_LINK_STATUS, &ok);
	return (ok ? prog : 0);
}

/* An attribute of floats in a buffer of stride floats a row, per
 * instance when so. */
static void
attrib(GLuint at, GLint n, int stride, int off, bool instanced)
{

	glEnableVertexAttribArray(at);
	glVertexAttribPointer(at, n, GL_FLOAT, GL_FALSE, stride *
	    (GLsizei)sizeof(float), (void *)(off * sizeof(float)));
	if (instanced)
		glVertexAttribDivisor(at, 1);
}

static bool
on_lost(int type, const void *reserved, void *data)
{

	gl.lost = true;
	return (true);
}

static int
wgl_open(void)
{
	EmscriptenWebGLContextAttributes	a;

	if (wgl.ctx > 0)
		emscripten_webgl_destroy_context(wgl.ctx);
	emscripten_webgl_init_context_attributes(&a);
	a.majorVersion = 2;
	a.minorVersion = 0;
	a.alpha = true;
	a.premultipliedAlpha = true;
	a.antialias = false;
	a.depth = false;
	a.stencil = false;
	a.powerPreference = EM_WEBGL_POWER_PREFERENCE_LOW_POWER;
	wgl.ctx = emscripten_webgl_create_context(GL_CANVAS, &a);
	if (wgl.ctx <= 0 || emscripten_webgl_make_context_current(wgl.ctx) !=
	    EMSCRIPTEN_RESULT_SUCCESS) {
		wgl.ctx = 0;
		return (-1);
	}
	if ((wgl.pprog = program(vs_src, fs_src)) == 0 || (wgl.sprog =
	    program(svs_src, sfs_src)) == 0)
		return (-1);
	wgl.ssize = glGetUniformLocation(wgl.sprog, "u_size");
	/* The points: a place, a size and a colour each. */
	glGenVertexArrays(1, &wgl.pvao);
	glBindVertexArray(wgl.pvao);
	glGenBuffers(1, &wgl.pvbo);
	glBindBuffer(GL_ARRAY_BUFFER, wgl.pvbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(gl.buf), NULL, GL_STREAM_DRAW);
	attrib(0, 2, PT_FLOATS, 0, false);
	attrib(1, 1, PT_FLOATS, 2, false);
	attrib(2, 4, PT_FLOATS, 3, false);
	/* The segments: two ends, a half width and a colour an instance. */
	glGenVertexArrays(1, &wgl.svao);
	glBindVertexArray(wgl.svao);
	glGenBuffers(1, &wgl.svbo);
	glBindBuffer(GL_ARRAY_BUFFER, wgl.svbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(gl.sbuf), NULL, GL_STREAM_DRAW);
	attrib(0, 2, SEG_FLOATS, 0, true);
	attrib(1, 2, SEG_FLOATS, 2, true);
	attrib(2, 1, SEG_FLOATS, 4, true);
	attrib(3, 4, SEG_FLOATS, 5, true);
	glEnable(GL_BLEND);
	glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
	emscripten_set_webglcontextlost_callback(GL_CANVAS, NULL, false,
	    on_lost);
	/* Restored: made anew from the scene, as lost. */
	emscripten_set_webglcontextrestored_callback(GL_CANVAS, NULL, false,
	    on_lost);
	return (1);
}

static bool
wgl_draw(int w, int h, const float *pts, int npts, const float *segs,
    int nsegs)
{

	if (emscripten_webgl_make_context_current(wgl.ctx) !=
	    EMSCRIPTEN_RESULT_SUCCESS)
		return (false);
	glViewport(0, 0, w, h);
	glClearColor(0, 0, 0, 0);
	glClear(GL_COLOR_BUFFER_BIT);
	if (nsegs > 0) {
		glUseProgram(wgl.sprog);
		glUniform2f(wgl.ssize, (float)w, (float)h);
		glBindVertexArray(wgl.svao);
		glBindBuffer(GL_ARRAY_BUFFER, wgl.svbo);
		glBufferSubData(GL_ARRAY_BUFFER, 0, (GLsizeiptr)nsegs *
		    SEG_FLOATS * sizeof(float), segs);
		glDrawArraysInstanced(GL_TRIANGLES, 0, 6, nsegs);
	}
	if (npts > 0) {
		glUseProgram(wgl.pprog);
		glBindVertexArray(wgl.pvao);
		glBindBuffer(GL_ARRAY_BUFFER, wgl.pvbo);
		glBufferSubData(GL_ARRAY_BUFFER, 0, (GLsizeiptr)npts * PT_FLOATS *
		    sizeof(float), pts);
		glDrawArrays(GL_POINTS, 0, npts);
	}
	return (true);
}

static void
wgl_close(void)
{

	if (wgl.ctx > 0)
		emscripten_webgl_destroy_context(wgl.ctx);
	wgl.ctx = 0;
}

static const struct backend webgl2 = { "webgl2", 1, wgl_open, wgl_draw,
    wgl_close };

/*
 * WebGPU.  One shader module, WGSL: a point and a segment are each a
 * quad of six corners made from the instance, the canvas's size in
 * pixels a uniform.  The device is asked for once and kept; a surface
 * is made on each canvas the page makes.
 */
static const char wgsl_src[] =
    "struct U { size : vec2f, pad : vec2f };\n"
    "@group(0) @binding(0) var<uniform> u : U;\n"
    "struct PIn { @location(0) pos : vec2f, @location(1) size : f32,\n"
    "    @location(2) col : vec4f };\n"
    "struct POut { @builtin(position) p : vec4f, @location(0) col : vec4f,\n"
    "    @location(1) uv : vec2f };\n"
    "const corner = array<vec2f, 6>(vec2f(-1, -1), vec2f(1, -1),\n"
    "    vec2f(-1, 1), vec2f(1, -1), vec2f(1, 1), vec2f(-1, 1));\n"
    "@vertex fn vs_point(@builtin(vertex_index) vi : u32, in : PIn) -> POut {\n"
    "    let k = corner[vi];\n"
    "    var o : POut;\n"
    "    o.p = vec4f(in.pos + k * in.size / u.size, 0.0, 1.0);\n"
    "    o.col = in.col;\n"
    "    o.uv = k;\n"
    "    return o;\n"
    "}\n"
    "@fragment fn fs_point(in : POut) -> @location(0) vec4f {\n"
    "    let r = length(in.uv);\n"
    "    let glow = 1.0 - smoothstep(0.0, 1.0, r);\n"
    "    let core = 1.0 - smoothstep(0.28, 0.42, r);\n"
    "    let a = clamp(glow * 0.7 + core, 0.0, 1.0) * in.col.a;\n"
    "    return vec4f(in.col.rgb * a, a);\n"
    "}\n"
    "struct SIn { @location(0) a : vec2f, @location(1) b : vec2f,\n"
    "    @location(2) hw : f32, @location(3) col : vec4f };\n"
    "struct SOut { @builtin(position) p : vec4f, @location(0) col : vec4f };\n"
    "const side = array<vec2f, 6>(vec2f(0, -1), vec2f(1, -1), vec2f(0, 1),\n"
    "    vec2f(1, -1), vec2f(1, 1), vec2f(0, 1));\n"
    "@vertex fn vs_seg(@builtin(vertex_index) vi : u32, in : SIn) -> SOut {\n"
    "    let k = side[vi];\n"
    "    let d = in.b - in.a;\n"
    "    let l = max(length(d), 0.001);\n"
    "    let n = vec2f(-d.y, d.x) / l;\n"
    "    let p = in.a + d * k.x + n * k.y * in.hw;\n"
    "    var o : SOut;\n"
    "    o.p = vec4f(p.x / u.size.x * 2.0 - 1.0, 1.0 - p.y / u.size.y * 2.0,\n"
    "        0.0, 1.0);\n"
    "    o.col = in.col;\n"
    "    return o;\n"
    "}\n"
    "@fragment fn fs_seg(in : SOut) -> @location(0) vec4f {\n"
    "    return vec4f(in.col.rgb * in.col.a, in.col.a);\n"
    "}\n";

static struct {
	WGPUInstance		 inst;
	WGPUAdapter		 adapter;
	WGPUDevice		 dev;
	WGPUQueue		 q;
	WGPUSurface		 surf;
	WGPUTextureFormat	 fmt;
	WGPURenderPipeline	 ppipe, spipe;
	WGPUBuffer		 pbuf, sbuf, ubuf;
	WGPUBindGroup		 pbg, sbg;
	int			 w, h;		/* the surface, as configured */
	int			 state;		/* 0 not asked, 1 asked, 2 a
						   device, -1 none here */
	int			 losts;		/* devices lost */
} gpu;

static WGPUStringView
sv(const char *s)
{
	WGPUStringView	v;

	v.data = s;
	v.length = WGPU_STRLEN;
	return (v);
}

/* The device went: made anew, from the scene, at the next frame. */
static void
gpu_lost(WGPUDevice const *device, WGPUDeviceLostReason reason,
    WGPUStringView message, void *u1, void *u2)
{

	char	why[200];

	snprintf(why, sizeof(why), "device lost (%d): %.*s", (int)reason,
	    (int)(message.length == WGPU_STRLEN ? strlen(message.data != NULL ?
	    message.data : "") : message.length), message.data != NULL ?
	    message.data : "");
	arc_gl_note(why);
	gpu.dev = NULL;
	gpu.q = NULL;
	gpu.ppipe = gpu.spipe = NULL;
	/* Asked for again; a browser that loses it thrice is left to
	 * WebGL 2. */
	gpu.state = ++gpu.losts >= 3 ? -1 : 0;
	gl.lost = true;
}

static void
gpu_device_cb(WGPURequestDeviceStatus status, WGPUDevice device,
    WGPUStringView message, void *u1, void *u2)
{

	if (status != WGPURequestDeviceStatus_Success || device == NULL) {
		gpu.state = -1;
		return;
	}
	/* Ours to keep: the callback's reference is the port's. */
	wgpuDeviceAddRef(device);
	gpu.dev = device;
	gpu.q = wgpuDeviceGetQueue(device);
	gpu.state = 2;
}

static void
gpu_adapter_cb(WGPURequestAdapterStatus status, WGPUAdapter adapter,
    WGPUStringView message, void *u1, void *u2)
{
	WGPUDeviceDescriptor		dd = WGPU_DEVICE_DESCRIPTOR_INIT;
	WGPURequestDeviceCallbackInfo	ci = WGPU_REQUEST_DEVICE_CALLBACK_INFO_INIT;

	if (status != WGPURequestAdapterStatus_Success || adapter == NULL) {
		gpu.state = -1;
		return;
	}
	wgpuAdapterAddRef(adapter);
	gpu.adapter = adapter;
	dd.label = sv("arcana map");
	dd.deviceLostCallbackInfo.mode = WGPUCallbackMode_AllowSpontaneous;
	dd.deviceLostCallbackInfo.callback = gpu_lost;
	ci.mode = WGPUCallbackMode_AllowSpontaneous;
	ci.callback = gpu_device_cb;
	wgpuAdapterRequestDevice(adapter, &dd, ci);
}

/* A pipeline of two of the module's entry points over an instance of
 * stride floats laid out as attrs says (n floats each, in order). */
static WGPURenderPipeline
gpu_pipeline(WGPUShaderModule mod, const char *vs, const char *fs,
    const int *attrs, int nattrs, int stride)
{
	WGPURenderPipelineDescriptor	d = WGPU_RENDER_PIPELINE_DESCRIPTOR_INIT;
	WGPUVertexBufferLayout		vb = WGPU_VERTEX_BUFFER_LAYOUT_INIT;
	WGPUVertexAttribute		at[4];
	WGPUFragmentState		fr = WGPU_FRAGMENT_STATE_INIT;
	WGPUColorTargetState		ct = WGPU_COLOR_TARGET_STATE_INIT;
	WGPUBlendState			bl = WGPU_BLEND_STATE_INIT;
	int				i, off;

	for (i = 0, off = 0; i < nattrs; i++) {
		at[i] = (WGPUVertexAttribute)WGPU_VERTEX_ATTRIBUTE_INIT;
		at[i].format = attrs[i] == 1 ? WGPUVertexFormat_Float32 :
		    attrs[i] == 2 ? WGPUVertexFormat_Float32x2 :
		    WGPUVertexFormat_Float32x4;
		at[i].offset = (uint64_t)off * sizeof(float);
		at[i].shaderLocation = (uint32_t)i;
		off += attrs[i];
	}
	vb.stepMode = WGPUVertexStepMode_Instance;
	vb.arrayStride = (uint64_t)stride * sizeof(float);
	vb.attributeCount = (size_t)nattrs;
	vb.attributes = at;
	d.vertex.module = mod;
	d.vertex.entryPoint = sv(vs);
	d.vertex.bufferCount = 1;
	d.vertex.buffers = &vb;
	d.primitive.topology = WGPUPrimitiveTopology_TriangleList;
	bl.color.operation = WGPUBlendOperation_Add;
	bl.color.srcFactor = WGPUBlendFactor_One;
	bl.color.dstFactor = WGPUBlendFactor_OneMinusSrcAlpha;
	bl.alpha = bl.color;
	ct.format = gpu.fmt;
	ct.blend = &bl;
	fr.module = mod;
	fr.entryPoint = sv(fs);
	fr.targetCount = 1;
	fr.targets = &ct;
	d.fragment = &fr;
	return (wgpuDeviceCreateRenderPipeline(gpu.dev, &d));
}

static WGPUBuffer
gpu_buffer(uint64_t size, WGPUBufferUsage usage)
{
	WGPUBufferDescriptor	d = WGPU_BUFFER_DESCRIPTOR_INIT;

	d.size = size;
	d.usage = usage | WGPUBufferUsage_CopyDst;
	return (wgpuDeviceCreateBuffer(gpu.dev, &d));
}

/* The uniform (the canvas's size), bound at group 0 of a pipeline. */
static WGPUBindGroup
gpu_bind(WGPURenderPipeline pipe)
{
	WGPUBindGroupDescriptor	d = WGPU_BIND_GROUP_DESCRIPTOR_INIT;
	WGPUBindGroupEntry	e = WGPU_BIND_GROUP_ENTRY_INIT;

	e.binding = 0;
	e.buffer = gpu.ubuf;
	e.offset = 0;
	e.size = 16;
	d.layout = wgpuRenderPipelineGetBindGroupLayout(pipe, 0);
	d.entryCount = 1;
	d.entries = &e;
	return (wgpuDeviceCreateBindGroup(gpu.dev, &d));
}

static int
gpu_open(void)
{
	WGPURequestAdapterOptions		ao = WGPU_REQUEST_ADAPTER_OPTIONS_INIT;
	WGPURequestAdapterCallbackInfo		ci = WGPU_REQUEST_ADAPTER_CALLBACK_INFO_INIT;
	WGPUEmscriptenSurfaceSourceCanvasHTMLSelector	cs =
	    WGPU_EMSCRIPTEN_SURFACE_SOURCE_CANVAS_HTML_SELECTOR_INIT;
	WGPUSurfaceDescriptor			sd = WGPU_SURFACE_DESCRIPTOR_INIT;
	WGPUSurfaceCapabilities			caps = WGPU_SURFACE_CAPABILITIES_INIT;
	WGPUShaderSourceWGSL			ws = WGPU_SHADER_SOURCE_WGSL_INIT;
	WGPUShaderModuleDescriptor		md = WGPU_SHADER_MODULE_DESCRIPTOR_INIT;
	WGPUShaderModule			mod;
	static const int			pat[] = { 2, 1, 4 };
	static const int			sat[] = { 2, 2, 1, 4 };

	if (gpu.state == -1)
		return (-1);
	if (gpu.state == 0) {
		/* The browser's WebGPU, if it has one, asked for a device:
		 * the answer comes on its own, between frames. */
		if (gpu.inst == NULL && (gpu.inst = wgpuCreateInstance(NULL)) ==
		    NULL) {
			gpu.state = -1;
			return (-1);
		}
		/* Held for good: a device outlives its instance's first
		 * reference otherwise (the port drops it under the device). */
		wgpuInstanceAddRef(gpu.inst);
		ao.powerPreference = WGPUPowerPreference_LowPower;
		ci.mode = WGPUCallbackMode_AllowSpontaneous;
		ci.callback = gpu_adapter_cb;
		wgpuInstanceRequestAdapter(gpu.inst, &ao, ci);
		gpu.state = 1;
		return (0);
	}
	if (gpu.state == 1)
		return (0);
	/* A device: a surface on this canvas, in the format it prefers. */
	if (gpu.surf != NULL)
		wgpuSurfaceRelease(gpu.surf);
	cs.selector = sv(GL_CANVAS);
	sd.nextInChain = &cs.chain;
	if ((gpu.surf = wgpuInstanceCreateSurface(gpu.inst, &sd)) == NULL ||
	    wgpuSurfaceGetCapabilities(gpu.surf, gpu.adapter, &caps) !=
	    WGPUStatus_Success || caps.formatCount == 0) {
		gpu.state = -1;
		return (-1);
	}
	gpu.fmt = caps.formats[0];
	wgpuSurfaceCapabilitiesFreeMembers(caps);
	gpu.w = gpu.h = 0;
	if (gpu.ppipe != NULL)
		return (1);
	ws.code = sv(wgsl_src);
	md.nextInChain = &ws.chain;
	md.label = sv("arcana map");
	if ((mod = wgpuDeviceCreateShaderModule(gpu.dev, &md)) == NULL) {
		gpu.state = -1;
		return (-1);
	}
	gpu.ubuf = gpu_buffer(16, WGPUBufferUsage_Uniform);
	gpu.pbuf = gpu_buffer(sizeof(gl.buf), WGPUBufferUsage_Vertex);
	gpu.sbuf = gpu_buffer(sizeof(gl.sbuf), WGPUBufferUsage_Vertex);
	gpu.ppipe = gpu_pipeline(mod, "vs_point", "fs_point", pat, 3, PT_FLOATS);
	gpu.spipe = gpu_pipeline(mod, "vs_seg", "fs_seg", sat, 4, SEG_FLOATS);
	wgpuShaderModuleRelease(mod);
	if (gpu.ppipe == NULL || gpu.spipe == NULL) {
		gpu.state = -1;
		return (-1);
	}
	gpu.pbg = gpu_bind(gpu.ppipe);
	gpu.sbg = gpu_bind(gpu.spipe);
	return (1);
}

static bool
gpu_draw(int w, int h, const float *pts, int npts, const float *segs,
    int nsegs)
{
	WGPUSurfaceConfiguration	sc = WGPU_SURFACE_CONFIGURATION_INIT;
	WGPUSurfaceTexture		st = WGPU_SURFACE_TEXTURE_INIT;
	WGPURenderPassColorAttachment	ca = WGPU_RENDER_PASS_COLOR_ATTACHMENT_INIT;
	WGPURenderPassDescriptor	rp = WGPU_RENDER_PASS_DESCRIPTOR_INIT;
	WGPUTextureView			view;
	WGPUCommandEncoder		enc;
	WGPURenderPassEncoder		pass;
	WGPUCommandBuffer		cb;
	float				u[4];

	if (gpu.dev == NULL)
		return (false);
	if (w != gpu.w || h != gpu.h) {
		sc.device = gpu.dev;
		sc.format = gpu.fmt;
		sc.width = (uint32_t)w;
		sc.height = (uint32_t)h;
		sc.alphaMode = WGPUCompositeAlphaMode_Premultiplied;
		sc.presentMode = WGPUPresentMode_Fifo;
		wgpuSurfaceConfigure(gpu.surf, &sc);
		gpu.w = w;
		gpu.h = h;
	}
	wgpuSurfaceGetCurrentTexture(gpu.surf, &st);
	if (st.status != WGPUSurfaceGetCurrentTextureStatus_SuccessOptimal &&
	    st.status != WGPUSurfaceGetCurrentTextureStatus_SuccessSuboptimal)
		return (false);
	view = wgpuTextureCreateView(st.texture, NULL);
	u[0] = (float)w;
	u[1] = (float)h;
	u[2] = u[3] = 0;
	wgpuQueueWriteBuffer(gpu.q, gpu.ubuf, 0, u, sizeof(u));
	if (nsegs > 0)
		wgpuQueueWriteBuffer(gpu.q, gpu.sbuf, 0, segs, (size_t)nsegs *
		    SEG_FLOATS * sizeof(float));
	if (npts > 0)
		wgpuQueueWriteBuffer(gpu.q, gpu.pbuf, 0, pts, (size_t)npts *
		    PT_FLOATS * sizeof(float));
	enc = wgpuDeviceCreateCommandEncoder(gpu.dev, NULL);
	ca.view = view;
	ca.loadOp = WGPULoadOp_Clear;
	ca.storeOp = WGPUStoreOp_Store;
	rp.colorAttachmentCount = 1;
	rp.colorAttachments = &ca;
	pass = wgpuCommandEncoderBeginRenderPass(enc, &rp);
	if (nsegs > 0) {
		wgpuRenderPassEncoderSetPipeline(pass, gpu.spipe);
		wgpuRenderPassEncoderSetBindGroup(pass, 0, gpu.sbg, 0, NULL);
		wgpuRenderPassEncoderSetVertexBuffer(pass, 0, gpu.sbuf, 0,
		    (uint64_t)nsegs * SEG_FLOATS * sizeof(float));
		wgpuRenderPassEncoderDraw(pass, 6, (uint32_t)nsegs, 0, 0);
	}
	if (npts > 0) {
		wgpuRenderPassEncoderSetPipeline(pass, gpu.ppipe);
		wgpuRenderPassEncoderSetBindGroup(pass, 0, gpu.pbg, 0, NULL);
		wgpuRenderPassEncoderSetVertexBuffer(pass, 0, gpu.pbuf, 0,
		    (uint64_t)npts * PT_FLOATS * sizeof(float));
		wgpuRenderPassEncoderDraw(pass, 6, (uint32_t)npts, 0, 0);
	}
	wgpuRenderPassEncoderEnd(pass);
	wgpuRenderPassEncoderRelease(pass);
	cb = wgpuCommandEncoderFinish(enc, NULL);
	wgpuQueueSubmit(gpu.q, 1, &cb);
	wgpuCommandBufferRelease(cb);
	wgpuCommandEncoderRelease(enc);
	wgpuTextureViewRelease(view);
	wgpuTextureRelease(st.texture);
	return (true);
}

static void
gpu_close(void)
{

	if (gpu.surf != NULL)
		wgpuSurfaceRelease(gpu.surf);
	gpu.surf = NULL;
	gpu.w = gpu.h = 0;
}

static const struct backend webgpu = { "webgpu", 2, gpu_open, gpu_draw,
    gpu_close };

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

/* Frames, until a frame finds nothing moving. */
static void
start(void)
{

	if (!gl.running && !gl.failed) {
		gl.running = true;
		emscripten_request_animation_frame_loop(frame, NULL);
	}
}

void
glmap_end(void)
{

	colours();
	start();
}

/*
 * The lines that move with the hand, given anew at each move of the
 * pointer: topo.c's link_geom() for every link of the host dragged, or
 * the one link bent.
 */
void
glmap_scene_begin(void)
{

	gl.ns = 0;
}

void
glmap_scene_link(double x1, double y1, double x2, double y2, double bend,
    double w, int kind, bool up, bool dim)
{
	struct glwire	*l;
	double		 dx, dy, len;

	if (gl.ns == GL_WIRES)
		return;
	l = &gl.s[gl.ns++];
	dx = x2 - x1;
	dy = y2 - y1;
	len = sqrt(dx * dx + dy * dy);
	if (len < 1)
		len = 1;
	l->x1 = (float)x1;
	l->y1 = (float)y1;
	l->x2 = (float)x2;
	l->y2 = (float)y2;
	l->cx = (float)((x1 + x2) / 2 - dy / len * bend);
	l->cy = (float)((y1 + y2) / 2 + dx / len * bend);
	l->w = (float)w;
	l->kind = kind >= 0 && kind < GL_KINDS ? kind : GL_KINDS - 1;
	l->up = up;
	l->dim = dim;
}

/* Drawn at the next frame: one, when nothing else moves. */
void
glmap_scene_end(void)
{

	colours();
	start();
}

/* The hand let go: the SVG's lines are back. */
void
glmap_scene_clear(void)
{

	gl.ns = 0;
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

/* A segment of a wire, in the canvas's pixels. */
static void
seg(double x0, double y0, double x1, double y1, double hw, const float *rgb,
    float a)
{
	float	*p;

	if (gl.segs == GL_SEGS_MAX)
		return;
	p = &gl.sbuf[gl.segs++ * SEG_FLOATS];
	p[0] = (float)x0;
	p[1] = (float)y0;
	p[2] = (float)x1;
	p[3] = (float)y1;
	p[4] = (float)hw;
	p[5] = rgb[0];
	p[6] = rgb[1];
	p[7] = rgb[2];
	p[8] = a;
}

/*
 * A wire as the SVG draws it: the curve in straight pieces, each as
 * wide as the wire is at this zoom; a link down at half strength, one
 * outside the table shown fainter still.
 */
static void
wire(const struct glwire *l)
{
	double	px[WIRE_SEGS + 1], py[WIRE_SEGS + 1], s, ox, oy, hw, t, u, x, y;
	float	a;
	int	i;

	s = fmin(gl.cw / gl.vw, gl.ch / gl.vh);
	ox = (gl.cw - gl.vw * s) / 2;
	oy = (gl.ch - gl.vh * s) / 2;
	for (i = 0; i <= WIRE_SEGS; i++) {
		t = (double)i / WIRE_SEGS;
		u = 1 - t;
		x = u * u * l->x1 + 2 * u * t * l->cx + t * t * l->x2;
		y = u * u * l->y1 + 2 * u * t * l->cy + t * t * l->y2;
		px[i] = ox + (x - gl.vx) * s;
		py[i] = oy + (y - gl.vy) * s;
	}
	hw = fmax(0.75, l->w * s / 2);
	a = l->dim ? 0.25f : l->up ? 0.85f : 0.45f;
	for (i = 0; i < WIRE_SEGS; i++)
		seg(px[i], py[i], px[i + 1], py[i + 1], hw, gl.rgb[l->kind], a);
}

/*
 * A backend for this canvas: WebGPU where the browser has it and gives
 * a device (asked for once; the frames go on until it answers), else
 * WebGL 2, else none and the SVG alone.  True when one can draw now.
 */
static bool
open_backend(int state)
{
	int	r;

	if (gl.be == NULL)
		gl.be = (state & 8) != 0 ? &webgpu : &webgl2;
	for (;;) {
		r = gl.be->open();
		if (r == 0)
			return (false);
		if (r > 0)
			break;
		if (gl.be == &webgpu) {
			/* A canvas that had a WebGPU context takes no other:
			 * WebGL 2 on a fresh one in its place. */
			gpu_close();
			arc_gl_fresh();
			gl.be = &webgl2;
			continue;
		}
		/* Not here: the SVG's own dashes, from the next draw on. */
		gl.failed = true;
		arc_gl_report(0, 0, 0, 0, 0, 0, gpu.state, gl.fails, gl.opens,
		    gpu.losts);
		render();
		return (false);
	}
	gl.opened = true;
	gl.lost = false;
	gl.cw = gl.ch = 0;
	gl.opens++;
	/* The SVG's dashes give way to this layer. */
	render();
	return (true);
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
	if (gl.failed)
		return (false);
	/* A canvas the page has just made, or a device or context lost:
	 * the backend on it anew, from the scene. */
	if ((state & 2) != 0 || gl.lost) {
		if (gl.opened)
			gl.be->close();
		gl.opened = false;
	}
	if (!gl.opened && !open_backend(state))
		return (!gl.failed);
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
	gl.points = 0;
	gl.segs = 0;
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
	/* The lines moving with the hand, under the points. */
	for (i = 0; i < gl.ns; i++)
		wire(&gl.s[i]);
	if (!gl.be->draw(w, h, gl.buf, gl.points, gl.sbuf, gl.segs)) {
		gl.lost = true;
		gl.fails++;
		return (true);
	}
	arc_gl_report(1, gl.points, flows, gl.np, gl.ns, gl.be->id, gpu.state,
	    gl.fails, gl.opens, gpu.losts);
	/* Nothing moves (the hand's lines are drawn once a move): the
	 * frames rest until the next draw. */
	if (gl.points == 0) {
		gl.running = false;
		return (false);
	}
	return (true);
}
