/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Browser APIs for the C application (an Emscripten --js-library).  Only
 * plumbing lives here: the application's logic, state and markup are C.
 *
 * C calls arc_*; the browser calls back into C through the exported
 * arc_on_* functions with strings in the wasm heap, which C frees.
 */

addToLibrary({
	$arcStr__deps: ["$stringToNewUTF8"],
	$arcStr: function (s) {
		return (stringToNewUTF8(s === null || s === undefined ?
		    "" : String(s)));
	},

	$arcB64: {
		enc: function (buf) {
			var b = new Uint8Array(buf), s = "", i;

			for (i = 0; i < b.length; i++)
				s += String.fromCharCode(b[i]);
			return (btoa(s).replace(/\+/g, "-").replace(/\//g, "_")
			    .replace(/=+$/, ""));
		},
		dec: function (s) {
			var t, b, i;

			s = s.replace(/-/g, "+").replace(/_/g, "/");
			while (s.length % 4 !== 0)
				s += "=";
			t = atob(s);
			b = new Uint8Array(t.length);
			for (i = 0; i < t.length; i++)
				b[i] = t.charCodeAt(i);
			return (b.buffer);
		}
	},

	/*
	 * Console plugins (the console's cplug.c, the page's plugins.c): the
	 * files of each plugin a console owner enabled, loaded with the
	 * integrity the console lists, and what their scripts are given,
	 * window.Arcana.  A plugin that fails, to load or as it runs, is
	 * told to the page as its error; the page goes on without it.
	 * What a plugin's code is called for is caught alike.  The C side
	 * is told by actions, after what it is doing is done.
	 */
	$arcPlug__deps: ["$arcStr"],
	$arcPlug: {
		plugins: {},	/* by id: { pending, reg, failed } */
		listed: null,	/* the list as last given */
		ev: {},		/* event: [{ id, fn }] */
		want: "",	/* the screen the address names */
		shown: null,	/* { id, name, rest, root, scr } */
		cur: "",	/* the plugin whose code runs now */
		servers: null,	/* the hosts as last told */
		user: { name: "", role: "" },
		version: "",
		events: ["route", "theme", "servers", "signed-out",
		    "gamepad-first"],

		act: function (a, b, c) {
			Promise.resolve().then(function () {
				Module._arc_on_action(arcStr(a), arcStr(b),
				    arcStr(c));
			});
		},
		fail: function (id, e) {
			var m = e && e.message ? e.message : String(e);

			if (arcPlug.plugins[id])
				arcPlug.plugins[id].failed = true;
			arcPlug.act("plugin-error", id, m.slice(0, 300));
		},
		/* A plugin's function called, what it throws its error. */
		call: function (id, fn, args) {
			var was = arcPlug.cur, r;

			if (typeof fn !== "function")
				return (undefined);
			arcPlug.cur = id;
			try {
				r = fn.apply(null, args);
			} catch (e) {
				arcPlug.fail(id, e);
			}
			arcPlug.cur = was;
			return (r);
		},
		/* The plugin whose script runs, or whose function. */
		whose: function () {
			var s = document.currentScript;

			return (s && s.dataset && s.dataset.plugin ?
			    s.dataset.plugin : arcPlug.cur);
		},
		/* An event to every plugin that listens; true when one of
		 * them took it (gamepad-first). */
		emit: function (name, data) {
			var took = false;

			(arcPlug.ev[name] || []).forEach(function (h) {
				if (arcPlug.call(h.id, h.fn, [data]) === true)
					took = true;
			});
			return (took);
		},
		on: function (id, name, fn) {
			if (arcPlug.events.indexOf(name) < 0)
				throw new Error("Arcana.on: no event " + name);
			if (typeof fn !== "function")
				throw new Error("Arcana.on: " + name +
				    ": not a function");
			(arcPlug.ev[name] = arcPlug.ev[name] || []).push({
			    id: id, fn: fn });
			/* The hosts as they are, not only when they change. */
			if (name === "servers" && arcPlug.servers !== null)
				arcPlug.call(id, fn, [arcPlug.servers]);
		},
		register: function (def) {
			var id = arcPlug.whose(), p = arcPlug.plugins[id], menu;

			if (!p)
				throw new Error("Arcana.registerPlugin: from " +
				    "a plugin's own script only");
			if (!def || def.id !== id)
				throw new Error("Arcana.registerPlugin: it is " +
				    "plugin " + id + ", not " + (def && def.id));
			if (p.reg)
				throw new Error("Arcana.registerPlugin: once");
			p.reg = def;
			Object.keys(def.on || {}).forEach(function (k) {
				arcPlug.on(id, k, def.on[k]);
			});
			menu = (def.menu || []).filter(function (m) {
				return (m && typeof m.label === "string" &&
				    typeof m.screen === "string" && def.screens &&
				    def.screens[m.screen]);
			}).map(function (m) {
				return ({ label: m.label, screen: m.screen });
			});
			if (menu.length > 0)
				arcPlug.act("plugin-menu", id, JSON.stringify(menu));
			/* Its screen named by the address before it was here. */
			if (arcPlug.want !== "" && arcPlug.shown === null)
				Promise.resolve().then(function () {
					arcPlug.screen(arcPlug.want, true);
				});
		},
		file: function (id, f) {
			return ("/plugins/" + encodeURIComponent(id) + "/" +
			    f.path.split("/").map(encodeURIComponent).join("/"));
		},
		/* Every plugin's files loaded, or failed: none is waited for. */
		settled: function () {
			return (Object.keys(arcPlug.plugins).every(function (id) {
				return (arcPlug.plugins[id].pending === 0);
			}));
		},
		done: function (id) {
			var p = arcPlug.plugins[id];

			if (--p.pending > 0)
				return;
			if (!p.failed)
				arcPlug.act("plugin-loaded", id, "");
			if (arcPlug.want !== "" && arcPlug.shown === null &&
			    arcPlug.settled())
				arcPlug.screen(arcPlug.want, true);
		},
		/*
		 * The list from GET /api/plugins: each enabled plugin with
		 * nothing wrong and not loaded yet, its styles and then its
		 * scripts in their order.  A plugin disabled since stays
		 * until the page is loaded again.
		 */
		load: function (text) {
			var list;

			if (text === arcPlug.listed)
				return;
			arcPlug.listed = text;
			try {
				list = JSON.parse(text).plugins || [];
			} catch (e) {
				return;
			}
			list.forEach(function (p) {
				var files = p.files || [], st, sc;

				if (!p.enabled || p.error || arcPlug.plugins[p.id])
					return;
				st = files.filter(function (f) {
					return (f.kind === "style");
				});
				sc = files.filter(function (f) {
					return (f.kind === "script");
				});
				arcPlug.plugins[p.id] = { pending: st.length +
				    sc.length + 1, reg: null, failed: false };
				st.forEach(function (f) {
					var el = document.createElement("link");

					el.rel = "stylesheet";
					el.integrity = f.integrity;
					el.crossOrigin = "anonymous";
					el.dataset.plugin = p.id;
					el.onload = function () {
						arcPlug.done(p.id);
					};
					el.onerror = function () {
						arcPlug.fail(p.id, "the browser would "
						    + "not use " + f.path + ": not "
						    + "served, or not as listed "
						    + "(integrity)");
						arcPlug.done(p.id);
					};
					el.href = arcPlug.file(p.id, f);
					document.head.appendChild(el);
				});
				sc.forEach(function (f) {
					var el = document.createElement("script");

					/* In their order, as they come. */
					el.async = false;
					el.integrity = f.integrity;
					el.crossOrigin = "anonymous";
					el.dataset.plugin = p.id;
					el.onload = function () {
						arcPlug.done(p.id);
					};
					el.onerror = function () {
						arcPlug.fail(p.id, "the browser would "
						    + "not run " + f.path + ": not "
						    + "served, or not as listed "
						    + "(integrity)");
						arcPlug.done(p.id);
					};
					el.src = arcPlug.file(p.id, f);
					document.head.appendChild(el);
				});
				arcPlug.done(p.id);
			});
		},
		/*
		 * The screen the address names (<plugin>/<screen>[/rest]),
		 * or none: a root over the whole page, the console's own
		 * regions put away under it, the plugin's enter() given the
		 * root and its ctx; leave() called, and the page as it was,
		 * when another is named or none.  A screen not there once
		 * every plugin is loaded is told to the page.
		 */
		screen: function (spec, again) {
			var parts = spec.split("/"), id = parts[0],
			    name = parts[1] || "", rest = parts.slice(2).join("/"),
			    s = arcPlug.shown, p, scr, root, ctx;

			if (spec === arcPlug.want && !again) {
				if (s !== null)
					document.title = (s.scr.title || s.name) +
					    " · Arcana";
				return;
			}
			arcPlug.want = spec;
			if (s !== null && (spec === "" || s.id !== id ||
			    s.name !== name))
				arcPlug.hide();
			else if (s !== null) {
				s.rest = s.ctx.rest = rest;
				return;
			}
			if (spec === "")
				return;
			p = arcPlug.plugins[id];
			scr = p && p.reg && p.reg.screens ? p.reg.screens[name] :
			    null;
			if (!scr || typeof scr.enter !== "function") {
				if (!p || arcPlug.settled())
					arcPlug.act("plugin-missing", spec, "");
				return;
			}
			root = document.createElement("div");
			root.id = "plug-root";
			root.className = "plug-root";
			root.dataset.plugin = id;
			root.dataset.screen = name;
			document.body.appendChild(root);
			document.documentElement.classList.add("plug-screen");
			ctx = { plugin: id, screen: name, rest: rest,
			    exit: function () {
				arcPlug.act("plugin-exit", id + "/" + name, "");
			    } };
			arcPlug.shown = { id: id, name: name, rest: rest,
			    root: root, scr: scr, ctx: ctx };
			document.title = (scr.title || name) + " · Arcana";
			arcPlug.call(id, scr.enter, [root, ctx]);
		},
		hide: function () {
			var s = arcPlug.shown;

			arcPlug.shown = null;
			arcPlug.call(s.id, s.scr.leave, []);
			s.root.remove();
			document.documentElement.classList.remove("plug-screen");
		},
		/* What a plugin's script is given. */
		init: function () {
			window.Arcana = Object.freeze({
				get version() {
					return (arcPlug.version);
				},
				get user() {
					return ({ name: arcPlug.user.name,
					    role: arcPlug.user.role });
				},
				registerPlugin: function (def) {
					arcPlug.register(def);
				},
				on: function (name, fn) {
					var id = arcPlug.whose();

					if (!arcPlug.plugins[id])
						throw new Error("Arcana.on: from a "
						    + "plugin's own code only");
					arcPlug.on(id, name, fn);
				},
				/* A request to the console as the page makes
				 * them: its own paths alone, JSON both ways. */
				api: function (method, url, body) {
					var o = { method: method || "GET",
					    credentials: "same-origin", headers: {
					    "X-Arcana": "1",
					    Accept: "application/json" } };

					if (typeof url !== "string" || url[0] !==
					    "/" || url[1] === "/")
						return (Promise.reject(new Error(
						    "Arcana.api: a path of the "
						    + "console's, as /api/...")));
					if (body !== undefined && body !== null) {
						o.headers["Content-Type"] =
						    "application/json";
						o.body = typeof body === "string" ?
						    body : JSON.stringify(body);
					}
					return (fetch(url, o).then(function (r) {
						return (r.text().then(function (t) {
							var j = null, e;

							try {
								j = t ? JSON.parse(t) :
								    null;
							} catch (x) {
							}
							if (r.ok)
								return (j);
							e = new Error(j && j.error ?
							    j.error.message ||
							    String(j.error) :
							    "HTTP " + r.status);
							e.status = r.status;
							e.body = j;
							throw e;
						}));
					}));
				},
				navigate: function (hash) {
					if (typeof hash === "string" &&
					    hash[0] === "#")
						location.hash = hash;
				},
				toast: function (text, bad) {
					arcPlug.act("plugin-toast", bad ? "1" : "",
					    String(text).slice(0, 300));
				},
				fullscreen: function (on) {
					var d = document;

					try {
						if (on && !d.fullscreenElement)
							d.documentElement
							    .requestFullscreen()
							    .catch(function () {});
						else if (!on && d.fullscreenElement)
							d.exitFullscreen()
							    .catch(function () {});
					} catch (e) {
					}
				}
			});
			/* An error thrown by a plugin's script: its own. */
			window.addEventListener("error", function (e) {
				var m = /\/plugins\/([a-z0-9-]+)\//.exec(
				    e.filename || "");

				if (m !== null && arcPlug.plugins[m[1]])
					arcPlug.fail(m[1], e.error || e.message);
			});
		}
	},

	/* The plugins' list (plugins.c), with who is signed in. */
	arc_plugins_set__deps: ["$arcPlug", "$UTF8ToString"],
	arc_plugins_set: function (listp, versionp, userp, rolep) {
		arcPlug.version = UTF8ToString(versionp);
		arcPlug.user = { name: UTF8ToString(userp),
		    role: UTF8ToString(rolep) };
		arcPlug.load(UTF8ToString(listp));
	},
	/* After each drawing: the plugin's screen to show, or "". */
	arc_plug_screen__deps: ["$arcPlug", "$UTF8ToString"],
	arc_plug_screen: function (specp) {
		arcPlug.screen(UTF8ToString(specp), false);
	},
	/* An event for the plugins, its data as JSON; after what the page
	 * does now is done. */
	arc_plug_event__deps: ["$arcPlug", "$UTF8ToString"],
	arc_plug_event: function (namep, jsonp) {
		var name = UTF8ToString(namep), data = null;

		try {
			data = JSON.parse(UTF8ToString(jsonp));
		} catch (e) {
		}
		if (name === "servers")
			arcPlug.servers = data;
		Promise.resolve().then(function () {
			arcPlug.emit(name, data);
		});
	},

	/*
	 * Replace the children of #id with html, keeping what has not
	 * changed (and the field being typed in) so transitions and focus
	 * survive re-rendering.
	 */
	arc_patch__deps: ["$UTF8ToString"],
	arc_patch: function (idp, htmlp) {
		var el = document.getElementById(UTF8ToString(idp));
		var html = UTF8ToString(htmlp);

		if (el === null)
			return;
		morphdom(el, "<div>" + html + "</div>", {
			childrenOnly: true,
			/*
			 * Keep the field being typed in, and every field
			 * somebody changed and the page did not: a box is
			 * drawn again under its fields when anything in it
			 * changes, an age that grew older say, and what
			 * was typed and not yet sent must still be there.
			 * A field the page itself gives another value is
			 * the page's.  Otherwise let morphdom walk:
			 * isEqualNode() on every node costs more than the
			 * walk, in Firefox several times.
			 */
			/*
			 * A box somebody opened or shut stays so: the page
			 * draws a <details> as it last chose, and what was
			 * pressed since is kept until the page itself
			 * draws it otherwise.
			 */
			onNodeAdded: function (node) {
				if (node.tagName === "DETAILS")
					node._arcOpen = node.hasAttribute("open");
				return (node);
			},
			onBeforeElUpdated: function (from, to) {
				var tag = from.tagName, i, was, now;

				/* An element the page draws into itself, a
				 * WebGL canvas: kept as it is. */
				if (from.hasAttribute("data-keep"))
					return (false);

				if (tag === "DETAILS") {
					now = to.hasAttribute("open");
					if (from._arcOpen === now) {
						if (from.open)
							to.setAttribute("open", "");
						else
							to.removeAttribute("open");
					}
					from._arcOpen = now;
					return (true);
				}
				if (tag !== "INPUT" && tag !== "TEXTAREA" &&
				    tag !== "SELECT")
					return (true);
				if (from === document.activeElement)
					return (false);
				if (tag === "SELECT") {
					was = now = -1;
					for (i = 0; i < from.options.length; i++)
						if (from.options[i].defaultSelected)
							was = i;
					for (i = 0; i < to.options.length; i++)
						if (to.options[i].defaultSelected)
							now = i;
					return (!(from.selectedIndex !==
					    Math.max(was, 0) && was === now &&
					    from.options.length ===
					    to.options.length));
				}
				if (from.type === "checkbox" ||
				    from.type === "radio")
					return (!(from.checked !==
					    from.defaultChecked &&
					    to.defaultChecked ===
					    from.defaultChecked));
				return (!(from.value !== from.defaultValue &&
				    to.defaultValue === from.defaultValue));
			}
		});
		if (typeof arcColsApply === "function")
			arcColsApply(el);
		if (typeof arcCards === "function")
			arcCards(el);
		if (typeof arcCsv === "function")
			arcCsv(el);
	},

	arc_set_class__deps: ["$UTF8ToString"],
	arc_set_class: function (idp, clsp, on) {
		var el = document.getElementById(UTF8ToString(idp));

		if (el !== null)
			el.classList.toggle(UTF8ToString(clsp), on !== 0);
	},

	arc_focus__deps: ["$UTF8ToString"],
	arc_focus: function (idp) {
		var el = document.getElementById(UTF8ToString(idp));

		if (el !== null)
			el.focus();
	},

	/*
	 * Events: clicks on [data-act], submitted forms (fields as a JSON
	 * object), typing in [data-input], Escape, network and visibility.
	 */
	arc_events_init__deps: ["$arcStr", "$arcPlug"],
	arc_events_init: function () {
		function act(name, arg, value) {
			var a = arcStr(name), b = arcStr(arg), c = arcStr(value);

			Module._arc_on_action(a, b, c);
		}

		arcPlug.init();
		document.addEventListener("click", function (e) {
			var t = e.target.closest("[data-act]"), more, c;

			/* A key or a value to paste elsewhere: copied, and
			 * the page told so it can say it was. */
			c = e.target.closest("[data-copy]");
			if (c !== null) {
				e.preventDefault();
				if (navigator.clipboard)
					navigator.clipboard.writeText(c.dataset.copy)
					    .then(function () {
						act("copied", "", "");
					}, function () {
						act("copied", "", "no");
					});
				return;
			}

			/*
			 * An error, a toast or one said in the page: its text
			 * copied when clicked (nothing selected in it, and
			 * not on a control of its own), to be pasted into a
			 * report; a toast then goes away as it did.
			 */
			c = e.target.closest(".toast.bad, .notice.bad, " +
			    ".notice.warn, p.error, .err, td.err");
			if (c !== null && e.target.closest("a, button, input, " +
			    "select, textarea, label") === null &&
			    String(window.getSelection()) === "" &&
			    navigator.clipboard) {
				navigator.clipboard.writeText(c.innerText.trim())
				    .then(function () {
					act("copied", "", "");
				}, function () {
					act("copied", "", "no");
				});
				if (!c.classList.contains("toast"))
					return;
			}

			/* A table as CSV. */
			c = e.target.closest("button.csv-btn");
			if (c !== null) {
				e.preventDefault();
				e.stopPropagation();
				arcCsvSave(c.closest("table"));
				return;
			}

			/* A row's ⋯: its actions shown or put away. */
			more = e.target.closest("button.acts-more");
			if (more !== null && typeof arcActsToggle === "function") {
				arcActsToggle(more);
				return;
			}

			if (t === null || t.disabled)
				return;
			if (t.tagName === "A" || t.tagName === "BUTTON")
				e.preventDefault();
			act(t.dataset.act, t.dataset.arg || "",
			    t.dataset.value || "");
		});
		/* Back, forward, or an address typed: go where it says. */
		window.addEventListener("popstate", function () {
			var h = location.hash;

			Module._arc_on_loc(arcStr(h));
			/* Said again otherwise: told by arc_loc_set. */
			if (location.hash === h)
				arcPlug.emit("route", { hash: h });
		});
		document.addEventListener("submit", function (e) {
			var f = e.target, o = {}, i, el;

			e.preventDefault();
			o.__submit = e.submitter && e.submitter.value ?
			    e.submitter.value : "";
			/* Of the buttons, only the one pressed says anything. */
			if (e.submitter && e.submitter.name)
				o[e.submitter.name] = e.submitter.value;
			for (i = 0; i < f.elements.length; i++) {
				el = f.elements[i];
				if (!el.name || el.tagName === "BUTTON")
					continue;
				/* Of a radio group, the one picked. */
				if (el.type === "radio" && !el.checked)
					continue;
				/* Of a select of several, every one picked,
				 * by commas, as a text field gives them. */
				o[el.name] = el.type === "checkbox" ?
				    el.checked : el.type === "select-multiple" ?
				    Array.from(el.selectedOptions, function (op) {
					    return (op.value);
				    }).join(", ") : el.value;
			}
			/* By its attribute: a field named dataset or id
			 * would stand for the form's own property. */
			act("submit:" + (f.getAttribute("data-form") ||
			    f.getAttribute("id") || ""), "",
			    JSON.stringify(o));
			/* A form that says so keeps no password once sent:
			 * the field shows what is kept again (its placeholder).
			 * Others, read again by a step that follows, keep it. */
			if (f.hasAttribute("data-clear-secrets"))
				for (i = 0; i < f.elements.length; i++)
					if (f.elements[i].type === "password")
						f.elements[i].value = "";
		});
		document.addEventListener("input", function (e) {
			var t = e.target;

			/* With its data-arg, which of several it is; a
			 * checkbox says true or false. */
			if (t.dataset && t.dataset.input)
				act("input:" + t.dataset.input, t.dataset.arg ||
				    "", t.type === "checkbox" ? (t.checked ?
				    "true" : "false") : t.value);
		});
		/*
		 * Keys: Escape closes what is open; inside something that
		 * names what its keys do (data-keys), a key not meant for a
		 * field or a button is handed to the page with the key's
		 * name and what has the focus (its data-arg).
		 */
		document.addEventListener("keydown", function (e) {
			var k, on;

			if (e.key === "Escape") {
				act("escape", "", "");
				return;
			}
			if (e.ctrlKey || e.metaKey || e.altKey || !e.target.closest)
				return;
			k = e.target.closest("[data-keys]");
			if (k === null || e.target.closest("input, select, " +
			    "textarea, button, a, summary, [contenteditable]") !==
			    null)
				return;
			on = e.target.closest("[data-arg]") || k;
			act(k.dataset.keys, e.key, on.dataset.arg || "");
			if (/^(Arrow|Enter| )/.test(e.key))
				e.preventDefault();
		});
		/* The map over the whole screen, or given back: the page is
		 * told by the browser's word (Escape leaves too). */
		document.addEventListener("fullscreenchange", function () {
			act("topo-fullscreen", document.fullscreenElement ?
			    "on" : "off", "");
		});

		/*
		 * A game controller: the console used by one alone (a Steam
		 * Deck in its Game Mode, the page a non-Steam game), by the
		 * Gamepad API.  While one is in use the root has the class
		 * pad: a visible focus, larger targets, and the buttons' words
		 * at the foot of the screen.  The D-pad and the left stick
		 * move the focus to the nearest control that way; A presses
		 * it (a field takes the screen's keyboard, Steam + X); B
		 * closes a dialog, else goes back; the bumpers go to the tab
		 * before or after, else to the side bar's page before or
		 * after; the right stick scrolls, or pans the network map;
		 * the triggers zoom it.  The standard mapping's buttons.
		 *
		 * Its first press is told to the plugins (gamepad-first); one
		 * that takes it has it alone.  A plugin's screen reads the
		 * controller itself: none of this while one is shown.
		 */
		var pad = { on: false, shown: false, frame: 0, held: {},
		    next: {}, hint: null, told: false, mute: false };

		function padVisible(el) {
			var r = el.getBoundingClientRect();

			return (r.width > 0 && r.height > 0 && r.bottom > 0 &&
			    r.right > 0 && r.top < window.innerHeight &&
			    r.left < window.innerWidth &&
			    getComputedStyle(el).visibility !== "hidden");
		}
		function padTargets() {
			var modal = document.querySelector(".modal"), all;

			all = (modal || document).querySelectorAll("a[href], " +
			    "button:not([disabled]), input:not([type=hidden]), " +
			    "select, textarea, summary, [data-act], " +
			    "[tabindex]:not([tabindex='-1'])");
			return (Array.prototype.filter.call(all, padVisible));
		}
		function padFocus(el) {
			if (!el.hasAttribute("tabindex") &&
			    !/^(A|BUTTON|INPUT|SELECT|TEXTAREA|SUMMARY)$/
			    .test(el.tagName))
				el.setAttribute("tabindex", "-1");
			el.focus({ preventScroll: true });
			el.scrollIntoView({ block: "nearest", inline: "nearest" });
		}
		/* The nearest control from the one in focus, toward dx, dy. */
		function padMove(dx, dy) {
			var cur = document.activeElement, list = padTargets(),
			    best = null, bd = Infinity, a, b, ox, oy, d, along,
			    across, i;

			if (list.length === 0)
				return;
			if (!cur || cur === document.body || list.indexOf(cur) < 0) {
				padFocus(list[0]);
				return;
			}
			a = cur.getBoundingClientRect();
			for (i = 0; i < list.length; i++) {
				if (list[i] === cur || cur.contains(list[i]) ||
				    list[i].contains(cur))
					continue;
				b = list[i].getBoundingClientRect();
				ox = (b.left + b.width / 2) - (a.left + a.width / 2);
				oy = (b.top + b.height / 2) - (a.top + a.height / 2);
				along = ox * dx + oy * dy;
				across = Math.abs(ox * dy - oy * dx);
				/* Ahead, and more ahead than aside. */
				if (along <= 0 || across > along * 2)
					continue;
				d = along + across * 2;
				if (d < bd) {
					bd = d;
					best = list[i];
				}
			}
			if (best !== null)
				padFocus(best);
		}
		/* A tab, else a side bar's page, before (-1) or after (1). */
		function padTab(dir) {
			var tabs = document.querySelector("nav.tabs"), list, i;

			list = tabs !== null ? tabs.querySelectorAll("button.tab") :
			    document.querySelectorAll("aside.rail li.titem");
			list = Array.prototype.filter.call(list, padVisible);
			if (list.length === 0)
				return;
			for (i = 0; i < list.length; i++)
				if (list[i].classList.contains("on") ||
				    list[i].classList.contains("selected") ||
				    list[i].getAttribute("aria-selected") === "true")
					break;
			i = i === list.length ? 0 : (i + dir + list.length) %
			    list.length;
			list[i].click();
		}
		function padPress() {
			var el = document.activeElement, o;

			if (!el || el === document.body) {
				padMove(0, 1);
				return;
			}
			if (el.tagName === "SELECT") {
				/* No list opens by script: the next choice. */
				o = el.selectedIndex + 1;
				el.selectedIndex = o >= el.options.length ? 0 : o;
				el.dispatchEvent(new Event("input", { bubbles: true }));
				el.dispatchEvent(new Event("change", { bubbles: true }));
				return;
			}
			if (el.tagName === "TEXTAREA" || (el.tagName === "INPUT" &&
			    !/^(checkbox|radio|button|submit|reset|file)$/
			    .test(el.type))) {
				el.focus();
				return;
			}
			el.click();
		}
		function padBack() {
			if (document.querySelector(".modal, .scrim") !== null)
				act("escape", "", "");
			else
				history.back();
		}
		/* The map, when it is shown: zoomed about its middle, panned
		 * by a drag of its ground. */
		function padMap(zoom, px, py) {
			var svg = document.querySelector("svg[data-wheel]"), r, m,
			    p, ground, o;

			if (svg === null || !padVisible(svg))
				return (false);
			r = svg.getBoundingClientRect();
			if (zoom !== 0 && (m = svg.getScreenCTM())) {
				p = new DOMPoint(r.left + r.width / 2, r.top +
				    r.height / 2).matrixTransform(m.inverse());
				act(svg.dataset.wheel, "", zoom + "," +
				    p.x.toFixed(1) + "," + p.y.toFixed(1));
			}
			ground = svg.querySelector("[data-drag]");
			if ((px !== 0 || py !== 0) && ground !== null) {
				o = { bubbles: true, pointerId: 7, button: 0,
				    clientX: r.left + r.width / 2,
				    clientY: r.top + r.height / 2 };
				ground.dispatchEvent(new PointerEvent("pointerdown", o));
				o.clientX -= px;
				o.clientY -= py;
				document.dispatchEvent(new PointerEvent("pointermove",
				    o));
				document.dispatchEvent(new PointerEvent("pointerup", o));
			}
			return (true);
		}
		/* A button pressed now, not held: and again while held. */
		function padEdge(k, down, now) {
			if (!down) {
				delete pad.held[k];
				return (false);
			}
			if (!pad.held[k]) {
				pad.held[k] = true;
				pad.next[k] = now + 350;
				return (true);
			}
			if (now >= pad.next[k]) {
				pad.next[k] = now + 110;
				return (true);
			}
			return (false);
		}
		/* A button pressed now, once however long it is held. */
		function padOnce(k, down) {
			var was = pad.held[k] === true;

			if (down)
				pad.held[k] = true;
			else
				delete pad.held[k];
			return (down && !was);
		}
		function padTick() {
			var gps = navigator.getGamepads ? navigator.getGamepads() :
			    [], g = null, i, now = performance.now(), b, ax;

			for (i = 0; i < gps.length; i++)
				if (gps[i] && gps[i].connected) {
					g = gps[i];
					break;
				}
			if (g === null) {
				padOff();
				return;
			}
			/* A plugin's screen: its input, and nothing here until
			 * every button is let go after it. */
			if (arcPlug.shown !== null) {
				if (pad.shown)
					padShow(false);
				pad.mute = true;
				pad.frame = requestAnimationFrame(padTick);
				return;
			}
			/* Used again after the mouse: shown again. */
			if (!pad.shown && (g.buttons.some(function (x) {
				return (x.pressed);
			}) || g.axes.some(function (v) {
				return (Math.abs(v) > 0.5);
			})))
				padShow(true);
			b = function (n) {
				return (g.buttons[n] !== undefined &&
				    g.buttons[n].pressed);
			};
			ax = function (n) {
				var v = g.axes[n] || 0;

				return (Math.abs(v) < 0.35 ? 0 : v);
			};
			if (pad.mute) {
				if (!g.buttons.some(function (x) {
					return (x.pressed);
				})) {
					pad.mute = false;
					pad.held = {};
				}
				pad.frame = requestAnimationFrame(padTick);
				return;
			}
			if (!pad.told && g.buttons.some(function (x) {
				return (x.pressed);
			})) {
				pad.told = true;
				if (arcPlug.emit("gamepad-first", { id: g.id })) {
					pad.mute = true;
					pad.frame = requestAnimationFrame(padTick);
					return;
				}
			}
			if (padEdge("up", b(12) || ax(1) < 0, now))
				padMove(0, -1);
			if (padEdge("down", b(13) || ax(1) > 0, now))
				padMove(0, 1);
			if (padEdge("left", b(14) || ax(0) < 0, now))
				padMove(-1, 0);
			if (padEdge("right", b(15) || ax(0) > 0, now))
				padMove(1, 0);
			if (padOnce("a", b(0)))
				padPress();
			if (padOnce("b", b(1)))
				padBack();
			if (padOnce("lb", b(4)))
				padTab(-1);
			if (padOnce("rb", b(5)))
				padTab(1);
			/* The triggers zoom, the right stick scrolls or pans. */
			if (padEdge("lt", b(6), now))
				padMap(100, 0, 0);
			if (padEdge("rt", b(7), now))
				padMap(-100, 0, 0);
			if (ax(2) !== 0 || ax(3) !== 0) {
				if (!padMap(0, ax(2) * 12, ax(3) * 12))
					(document.scrollingElement || document.body)
					    .scrollBy(ax(2) * 18, ax(3) * 18);
			}
			pad.frame = requestAnimationFrame(padTick);
		}
		/* A controller's look, and the buttons' words, on or off. */
		function padShow(on) {
			pad.shown = on;
			document.documentElement.classList.toggle("pad", on);
			if (on && pad.hint === null) {
				pad.hint = document.createElement("div");
				pad.hint.className = "padhint";
				pad.hint.setAttribute("aria-hidden", "true");
				pad.hint.innerHTML = "<span><b>D-pad</b> Move</span>" +
				    "<span><b>A</b> Press</span><span><b>B</b> " +
				    "Back</span><span><b>LB RB</b> Tabs</span>" +
				    "<span><b>R stick</b> Scroll</span><span><b>" +
				    "LT RT</b> Zoom the map</span><span><b>Steam + " +
				    "X</b> Keyboard</span>";
				document.body.appendChild(pad.hint);
			} else if (!on && pad.hint !== null) {
				pad.hint.remove();
				pad.hint = null;
			}
		}
		function padOn() {
			if (pad.on)
				return;
			pad.on = true;
			padShow(true);
			pad.frame = requestAnimationFrame(padTick);
		}
		function padOff() {
			if (!pad.on)
				return;
			pad.on = false;
			cancelAnimationFrame(pad.frame);
			padShow(false);
			pad.held = {};
		}
		window.addEventListener("gamepadconnected", padOn);
		/* The mouse or a touch: the page as it is without one, until
		 * the controller is used again. */
		document.addEventListener("pointerdown", function (e) {
			if (pad.shown && e.isTrusted)
				padShow(false);
		}, true);
		/* A file picked in [data-file]: its text given to the page,
		 * as file:<what> with the file's name; the field emptied, so
		 * that the same file can be picked again. */
		document.addEventListener("change", function (e) {
			var t = e.target, f, r;

			if (t.type !== "file" || !t.dataset || !t.dataset.file ||
			    t.files.length === 0)
				return;
			f = t.files[0];
			if (f.size > 4 * 1024 * 1024) {
				act("file:" + t.dataset.file, f.name, "");
				t.value = "";
				return;
			}
			r = new FileReader();
			r.onload = function () {
				act("file:" + t.dataset.file, f.name,
				    String(r.result));
				t.value = "";
			};
			r.readAsText(f);
		});
		/*
		 * A file picked in [data-upload]: sent as it is, bytes, to
		 * the console at data-url, in parts of 4 MB (a body may be 8
		 * unless web.conf says more), each where the one before ended
		 * (&offset=), the last said (&last=1); the page hears
		 * upload:<what> with the file's name and {"sent", "size"} as
		 * it goes, then the console's answer to the last part, or
		 * {"error"}.
		 */
		document.addEventListener("change", function (e) {
			var t = e.target, f, part = 4 * 1024 * 1024, what, url;

			if (t.type !== "file" || !t.dataset || !t.dataset.upload ||
			    !t.dataset.url || t.files.length === 0)
				return;
			f = t.files[0];
			what = "upload:" + t.dataset.upload;
			url = t.dataset.url + (t.dataset.url.indexOf("?") < 0 ?
			    "?" : "&") + "file=" + encodeURIComponent(f.name);
			t.value = "";
			(function send(off) {
				var end = Math.min(f.size, off + part),
				    last = end >= f.size;

				act(what, f.name, JSON.stringify({ sent: off,
				    size: f.size }));
				fetch(url + "&offset=" + off + (last ? "&last=1" :
				    ""), {
					method: "POST",
					credentials: "same-origin",
					cache: "no-store",
					headers: { "Content-Type":
					    "application/octet-stream",
					    "X-Arcana": "1" },
					body: f.slice(off, end)
				}).then(function (r) {
					return (r.text().then(function (b) {
						if (r.status !== 200) {
							var m = b, j;

							try {
								j = JSON.parse(b);
								m = (j.error &&
								    j.error.message) || b;
							} catch (x) {
							}
							act(what, f.name, JSON.stringify({
							    error: String(m || r.status) }));
						} else if (!last)
							send(end);
						else
							act(what, f.name, b);
					}));
				}).catch(function (err) {
					act(what, f.name, JSON.stringify({ error:
					    String(err) }));
				});
			})(0);
		});

		/*
		 * Rows put in another order by dragging: a row with
		 * data-reorder is taken with its data-arg, and dropped on
		 * another of the same data-reorder, before or after it by
		 * which half of it the pointer is in; the page hears
		 * <data-reorder>-drop with what was taken, and the row and
		 * the side ("1001:before").
		 */
		var reordering = null;

		function rowOf(e) {
			var r = e.target.closest ? e.target.closest(
			    "[data-reorder]") : null;

			return (r !== null && reordering !== null &&
			    r.dataset.reorder === reordering.dataset.reorder &&
			    r !== reordering ? r : null);
		}
		function side(r, e) {
			var b = r.getBoundingClientRect();

			return (e.clientY < b.top + b.height / 2 ? "before" :
			    "after");
		}
		function unmark() {
			document.querySelectorAll(".drop-before, .drop-after")
			    .forEach(function (x) {
				x.classList.remove("drop-before", "drop-after");
			});
		}
		document.addEventListener("dragstart", function (e) {
			var r = e.target.closest ? e.target.closest(
			    "[data-reorder]") : null;

			if (r === null)
				return;
			reordering = r;
			r.classList.add("dragging");
			e.dataTransfer.effectAllowed = "move";
			e.dataTransfer.setData("text/plain", r.dataset.arg || "");
		});
		document.addEventListener("dragover", function (e) {
			var r = rowOf(e);

			if (r === null)
				return;
			e.preventDefault();
			unmark();
			r.classList.add("drop-" + side(r, e));
		});
		document.addEventListener("drop", function (e) {
			var r = rowOf(e);

			if (r === null)
				return;
			e.preventDefault();
			act(reordering.dataset.reorder + "-drop",
			    reordering.dataset.arg || "", (r.dataset.arg || "") +
			    ":" + side(r, e));
		});
		document.addEventListener("dragend", function () {
			if (reordering !== null)
				reordering.classList.remove("dragging");
			reordering = null;
			unmark();
		});

		/*
		 * What is taken from a palette, [data-palette] with its
		 * data-arg, and dropped on a drawing in [data-dropzone]:
		 * the page hears <zone>-drop with what it was and where in
		 * the drawing, "x,y".
		 */
		var palette = null;

		document.addEventListener("dragstart", function (e) {
			var t = e.target.closest ? e.target.closest(
			    "[data-palette]") : null;

			if (t === null)
				return;
			palette = t.dataset.arg || "";
			e.dataTransfer.effectAllowed = "copy";
			e.dataTransfer.setData("text/plain", palette);
		});
		document.addEventListener("dragover", function (e) {
			if (palette !== null && e.target.closest &&
			    e.target.closest("[data-dropzone]") !== null) {
				e.preventDefault();
				e.dataTransfer.dropEffect = "copy";
			}
		});
		document.addEventListener("drop", function (e) {
			var z, svg, m, p, what = palette;

			palette = null;
			if (what === null || !e.target.closest ||
			    (z = e.target.closest("[data-dropzone]")) === null)
				return;
			e.preventDefault();
			svg = z.querySelector("svg");
			m = svg !== null ? svg.getScreenCTM() : null;
			p = m !== null ? new DOMPoint(e.clientX, e.clientY)
			    .matrixTransform(m.inverse()) : { x: 0, y: 0 };
			act(z.dataset.dropzone + "-drop", what,
			    p.x.toFixed(1) + "," + p.y.toFixed(1));
		});
		document.addEventListener("dragend", function () {
			palette = null;
		});

		/*
		 * Things dragged inside a drawing: an element with data-drag
		 * names what it is, and the page hears of it as
		 * <name>-start where it was taken hold of, <name>-move
		 * while it is dragged, <name>-end when let go,
		 * with what it was dropped on (the nearest data-drop), or
		 * <name>-click when it was not moved.  The value is
		 * "x,y,cx,cy,k[,drop]": where in the drawing, where on the
		 * screen, and how much of the drawing a pixel is.
		 */
		var drag = null;

		/* Where in the drawing a point of the screen is, or null. */
		function inside(cx, cy) {
			var m = drag.svg.getScreenCTM();

			return (m ? new DOMPoint(cx, cy).matrixTransform(
			    m.inverse()) : null);
		}
		function where(e) {
			var m = drag.svg.getScreenCTM(), p;

			if (!m)
				return ("0,0," + e.clientX + "," + e.clientY + ",1");
			p = new DOMPoint(e.clientX, e.clientY)
			    .matrixTransform(m.inverse());
			return (p.x.toFixed(1) + "," + p.y.toFixed(1) + "," +
			    e.clientX + "," + e.clientY + "," +
			    (1 / m.a).toFixed(4));
		}
		/*
		 * What says data-follow goes with the hand by its own
		 * transform, from where it was when taken hold of, without
		 * waiting for the page to draw it there: the page's own
		 * redraw, when it comes, puts it in the same place.
		 */
		function follow(e) {
			var p = inside(e.clientX, e.clientY), el = drag.el;

			if (p === null || drag.p0 === undefined)
				return;
			if (!document.contains(el))
				el = drag.el = drag.svg.querySelector("[data-drag=\"" +
				    drag.name + "\"][data-arg=\"" + CSS.escape(drag.arg) +
				    "\"]");
			if (el !== null)
				el.setAttribute("transform", "translate(" + (drag.fx +
				    p.x - drag.p0.x).toFixed(1) + "," + (drag.fy + p.y -
				    drag.p0.y).toFixed(1) + ")");
		}
		document.addEventListener("pointerdown", function (e) {
			var t = e.target.closest ? e.target.closest(
			    "[data-drag]") : null, svg, a;

			if (t === null || e.button > 0)
				return;
			/* A button inside what is dragged (Draw mode's ring
			 * on a host's port) is pressed, not dragged. */
			a = e.target.closest("[data-act]");
			if (a !== null && t.contains(a))
				return;
			svg = t.closest("svg");
			if (svg === null)
				return;
			if (drag !== null)
				return;
			drag = { name: t.dataset.drag, arg: t.dataset.arg || "",
			    svg: svg, svgid: svg.id, x: e.clientX, y: e.clientY,
			    moved: false, last: null, frame: 0, id: e.pointerId,
			    el: t, follow: t.hasAttribute("data-follow") };
			/*
			 * The pointer is the drawing's until let go: over
			 * the panels, outside the window, it still moves
			 * what it holds, and its letting go is heard.
			 */
			try {
				svg.setPointerCapture(e.pointerId);
			} catch (err) {
			}
			e.preventDefault();
		});
		document.addEventListener("pointermove", function (e) {
			if (drag === null || (e.pointerId !== drag.id &&
			    e.isTrusted))
				return;
			if (!drag.moved && Math.abs(e.clientX - drag.x) +
			    Math.abs(e.clientY - drag.y) < 5)
				return;
			if (!drag.moved) {
				var tr;

				/* Where it was taken hold of, before it moves. */
				drag.moved = true;
				if (drag.follow) {
					tr = /translate\(\s*([-\d.]+)[ ,]+([-\d.]+)/.exec(
					    drag.el.getAttribute("transform") || "");
					drag.fx = tr ? parseFloat(tr[1]) : 0;
					drag.fy = tr ? parseFloat(tr[2]) : 0;
					drag.p0 = inside(drag.x, drag.y) || undefined;
				}
				act(drag.name + "-start", drag.arg, where({
				    clientX: drag.x, clientY: drag.y }));
				if (drag === null)
					return;
			}
			drag.last = e;
			/* Once a frame is as often as it can be drawn. */
			if (drag.frame === 0)
				drag.frame = requestAnimationFrame(function () {
					if (drag === null)
						return;
					drag.frame = 0;
					if (!document.contains(drag.svg))
						drag.svg = (drag.svgid &&
						    document.getElementById(
						    drag.svgid)) || document.
						    querySelector("svg.topo") ||
						    drag.svg;
					if (drag.follow)
						follow(drag.last);
					act(drag.name + "-move", drag.arg,
					    where(drag.last));
				});
		});
		function drop(e) {
			var d = drag, el, on;

			if (d === null || (e.pointerId !== d.id && e.isTrusted))
				return;
			drag = null;
			if (d.frame !== 0)
				cancelAnimationFrame(d.frame);
			if (!d.moved) {
				act(d.name + "-click", d.arg, "");
				return;
			}
			if (!document.contains(d.svg))
				d.svg = (d.svgid && document.getElementById(
				    d.svgid)) || document.querySelector(
				    "svg.topo") || d.svg;
			drag = d;
			el = document.elementFromPoint(e.clientX, e.clientY);
			on = el && el.closest ? el.closest("[data-drop]") : null;
			el = where(e) + "," + (on ? on.dataset.drop : "");
			drag = null;
			act(d.name + "-end", d.arg, el);
		}
		document.addEventListener("pointerup", drop);
		document.addEventListener("pointercancel", drop);

		/*
		 * Two fingers on a drawing that zooms: as they part or
		 * close, the drawing grows or shrinks about the point
		 * between them.  The page hears of it as the wheel's name
		 * with "pinch" and "factor,x,y".  A drag begun by the first
		 * finger is dropped when the second comes down.
		 */
		var pinch = { pts: {}, n: 0, svg: null, dist: 0 };

		function pinchDist() {
			var k = Object.keys(pinch.pts), a, b;

			if (k.length < 2)
				return (0);
			a = pinch.pts[k[0]];
			b = pinch.pts[k[1]];
			return (Math.hypot(a.x - b.x, a.y - b.y));
		}
		document.addEventListener("pointerdown", function (e) {
			var svg = e.target.closest ? e.target.closest(
			    "svg[data-wheel]") : null;

			if (svg === null || e.pointerType !== "touch")
				return;
			pinch.pts[e.pointerId] = { x: e.clientX, y: e.clientY };
			pinch.n = Object.keys(pinch.pts).length;
			if (pinch.n === 2) {
				pinch.svg = svg;
				pinch.dist = pinchDist();
				if (drag !== null && drag.frame !== 0)
					cancelAnimationFrame(drag.frame);
				drag = null;
			}
		});
		document.addEventListener("pointermove", function (e) {
			var k, a, b, d, m, p;

			if (!(e.pointerId in pinch.pts))
				return;
			pinch.pts[e.pointerId] = { x: e.clientX, y: e.clientY };
			if (pinch.svg === null || pinch.n !== 2)
				return;
			e.preventDefault();
			d = pinchDist();
			if (pinch.dist <= 0 || Math.abs(d - pinch.dist) < 3)
				return;
			if (!document.contains(pinch.svg))
				pinch.svg = document.querySelector(
				    "svg[data-wheel]") || pinch.svg;
			if (!(m = pinch.svg.getScreenCTM()))
				return;
			k = Object.keys(pinch.pts);
			a = pinch.pts[k[0]];
			b = pinch.pts[k[1]];
			p = new DOMPoint((a.x + b.x) / 2, (a.y + b.y) / 2)
			    .matrixTransform(m.inverse());
			act(pinch.svg.dataset.wheel, "pinch", (d /
			    pinch.dist).toFixed(4) + "," + p.x.toFixed(1) +
			    "," + p.y.toFixed(1));
			pinch.dist = d;
		}, { passive: false });
		function pinchEnd(e) {
			if (!(e.pointerId in pinch.pts))
				return;
			delete pinch.pts[e.pointerId];
			pinch.n = Object.keys(pinch.pts).length;
			if (pinch.n < 2)
				pinch.svg = null;
		}
		document.addEventListener("pointerup", pinchEnd);
		document.addEventListener("pointercancel", pinchEnd);
		/*
		 * Every table's columns are as wide as they are dragged:
		 * a head's right border is taken hold of and moved, and a
		 * double click on it lets the column be as wide as what is
		 * in it again.  A width is kept, while the page lives, by
		 * the table's kind and the column's place, and put back
		 * when the table is drawn again.
		 */
		var colw = {}, coldrag = null, colclick = 0;

		function colKey(th) {
			var t = th.closest("table");

			return (t === null ? null : t.className.replace(
			    /\s+/g, ".") + "#" + th.cellIndex);
		}
		function colEdge(e) {
			var th = e.target.closest ? e.target.closest(
			    "table.net th") : null, r;

			if (th === null)
				return (null);
			r = th.getBoundingClientRect();
			/* A click made by a script has no place: not a border's. */
			if (e.clientX < r.left || e.clientX > r.right ||
			    e.clientY < r.top || e.clientY > r.bottom)
				return (null);
			if (r.right - e.clientX <= 6)
				return (th);
			/* The left border is the one before's right. */
			if (e.clientX - r.left <= 4 &&
			    th.previousElementSibling !== null)
				return (th.previousElementSibling);
			return (null);
		}
		/*
		 * On a phone a table is a card for each row: each cell says
		 * which column it is of, taken from the table's head, which
		 * stays as a row of buttons to sort by.  A row of one cell
		 * across the table (one being changed, say) stays as it is.
		 */
		/*
		 * The column a card is titled by: the one that names the row
		 * (a process's command, an interface's name), not its first
		 * when that is a number; -1 when none is better than the
		 * first.
		 */
		var TITLES = ["name", "command", "interface", "jail",
		    "service", "dataset", "package", "connection", "pool",
		    "disk", "device", "protocol", "peer", "snapshot",
		    "address", "destination", "host", "part"];

		function cardTitle(labels) {
			var t, k;

			for (t = 0; t < TITLES.length; t++)
				for (k = 0; k < labels.length; k++)
					if (labels[k].toLowerCase() === TITLES[t])
						return (k);
			return (-1);
		}
		/*
		 * A card's actions, when there are more than two, behind one
		 * button that shows them; which cards were opened is kept
		 * while the page is drawn again, by the card's title.
		 */
		var actsOpen = {};

		window.arcActsToggle = function (more) {
			var td = more.parentElement;

			actsOpen[more.dataset.key] = !td.classList.contains(
			    "open");
			td.classList.toggle("open");
		};

		function cardActs(t, tr, most) {
			var td = tr.querySelector("td.acts"), more, key, n;

			if (td === null)
				return;
			n = td.querySelectorAll("button:not(.acts-more)").length;
			more = td.querySelector("button.acts-more");
			if (n <= most) {
				if (more !== null)
					more.remove();
				td.classList.remove("many");
				return;
			}
			key = (t.className || "") + "|" + ((tr.querySelector(
			    "td.ctitle") || tr.firstElementChild).textContent ||
			    "");
			td.classList.add("many");
			if (more === null) {
				more = document.createElement("button");
				more.type = "button";
				more.className = "ghost small acts-more";
				more.title = "Its actions";
				more.textContent = "…";
				more.setAttribute("aria-label", "More actions");
				/* No listener of its own: the page's one
				 * click handler toggles it (arcActsToggle),
				 * since morphdom may make this element
				 * another button. */
				td.appendChild(more);
			}
			more.dataset.key = key;
			td.classList.toggle("open", actsOpen[key] === true);
		}

		/*
		 * Every table can be had as CSV: a button in the last cell
		 * of its head (drawn by CSS, so the head's words stay as
		 * they are), made again after each patch.
		 */
		window.arcCsv = function (root) {
			var hs = root.querySelectorAll("table > thead > tr:first-child"),
			    i, last, b;

			for (i = 0; i < hs.length; i++) {
				last = hs[i].lastElementChild;
				if (last === null || last.querySelector(
				    "button.csv-btn") !== null)
					continue;
				b = document.createElement("button");
				b.type = "button";
				b.className = "csv-btn";
				b.title = "These rows as CSV";
				b.setAttribute("aria-label", "These rows as CSV");
				last.appendChild(b);
			}
		};

		/* A cell's words, without its buttons, on one line. */
		function cellText(c) {
			var k = c.cloneNode(true), x, i;

			x = k.querySelectorAll("button, input, select, textarea, " +
			    "svg, .acts-more");
			for (i = 0; i < x.length; i++)
				x[i].remove();
			return (k.textContent.replace(/\s+/g, " ").trim());
		}

		/*
		 * A cell a spreadsheet would read as a formula (a name a host
		 * or jail chose, say "=cmd|...") is made text by a leading
		 * quote; a number, negative ones too, stays a number.
		 */
		function csvField(v) {
			if (/^[=+@\t\r]/.test(v) || (/^-./.test(v) &&
			    !/^-[0-9.,]+%?$/.test(v)))
				v = "'" + v;
			return (/[",\n\r]/.test(v) ? "\"" + v.replace(/"/g,
			    "\"\"") + "\"" : v);
		}

		/* The table's rows as shown, as a file to save. */
		window.arcCsvSave = function (table) {
			var ths = table.querySelectorAll("thead > tr:first-child > th"),
			    rows = table.querySelectorAll("tbody > tr"), n, i, j,
			    out = [], line, tds, h, name, a, url;

			/* Columns: up to the last one with a name; those after
			 * it hold buttons. */
			for (n = ths.length; n > 0 && cellText(ths[n - 1]) ===
			    ""; n--)
				;
			line = [];
			for (i = 0; i < n; i++)
				line.push(csvField(cellText(ths[i])));
			out.push(line.join(","));
			for (i = 0; i < rows.length; i++) {
				tds = rows[i].children;
				if (tds.length < n)
					continue;
				line = [];
				for (j = 0; j < n; j++)
					line.push(csvField(cellText(tds[j])));
				out.push(line.join(","));
			}
			/* Named by the heading it is under. */
			h = null;
			for (a = table; a !== null && h === null; a =
			    a.parentElement)
				h = a.querySelector("h2, h3, h4");
			name = ((h !== null ? cellText(h) : "") || "table")
			    .toLowerCase().replace(/[^a-z0-9]+/g, "-")
			    .replace(/^-|-$/g, "").slice(0, 40) || "table";
			url = URL.createObjectURL(new Blob([out.join("\n") +
			    "\n"], { type: "text/csv" }));
			a = document.createElement("a");
			a.href = url;
			a.download = name + ".csv";
			document.body.appendChild(a);
			a.click();
			a.remove();
			setTimeout(function () { URL.revokeObjectURL(url); },
			    1000);
			window.arcCsvLast = out.join("\n");
		};

		window.arcCards = function (root) {
			var narrow = window.matchMedia("(max-width: 620px)")
			    .matches, ts, t, ths, labels, rows, tds, i, j, k,
			    title;

			ts = root.querySelectorAll("table.net");
			for (i = 0; i < ts.length; i++) {
				t = ts[i];
				/*
				 * On a wide screen a row keeps three of its
				 * actions in sight, the first two and the one
				 * that shows the rest.
				 */
				if (!narrow) {
					t.classList.remove("cards");
					rows = t.querySelectorAll("tbody > tr");
					for (j = 0; j < rows.length; j++)
						cardActs(t, rows[j], 3);
					continue;
				}
				t.classList.add("cards");
				ths = t.querySelectorAll("thead th");
				labels = [];
				for (j = 0; j < ths.length; j++)
					labels.push(ths[j].textContent.trim());
				title = cardTitle(labels);
				rows = t.querySelectorAll("tbody > tr");
				for (j = 0; j < rows.length; j++) {
					tds = rows[j].children;
					if (tds.length !== labels.length) {
						rows[j].classList.add("whole");
						continue;
					}
					for (k = 0; k < tds.length; k++) {
						if (tds[k].dataset.label !==
						    labels[k])
							tds[k].dataset.label =
							    labels[k];
						tds[k].classList.toggle("ctitle",
						    k === title);
					}
					rows[j].classList.toggle("titled",
					    title > 0);
					cardActs(t, rows[j], 2);
				}
			}
		};
		window.arcColsApply = function (root) {
			var ths = root.querySelectorAll("table.net th"), i, k;

			for (i = 0; i < ths.length; i++) {
				k = colKey(ths[i]);
				if (k !== null && colw[k] !== undefined) {
					ths[i].style.width = colw[k] + "px";
					ths[i].style.minWidth = colw[k] + "px";
					ths[i].style.maxWidth = colw[k] + "px";
				} else if (ths[i].style.width !== "") {
					ths[i].style.width = "";
					ths[i].style.minWidth = "";
					ths[i].style.maxWidth = "";
				}
			}
		};
		document.addEventListener("pointermove", function (e) {
			var th, w;

			if (coldrag !== null) {
				w = Math.max(40, coldrag.w + e.clientX -
				    coldrag.x);
				colw[coldrag.k] = Math.round(w);
				arcColsApply(document);
				return;
			}
			th = e.target.closest ? e.target.closest(
			    "table.net thead") : null;
			if (th !== null)
				th.style.cursor = colEdge(e) !== null ?
				    "col-resize" : "";
		});
		document.addEventListener("pointerdown", function (e) {
			var th = colEdge(e);

			if (th === null || e.button > 0)
				return;
			coldrag = { k: colKey(th), x: e.clientX,
			    w: th.getBoundingClientRect().width };
			e.preventDefault();
			e.stopPropagation();
		}, true);
		document.addEventListener("pointerup", function () {
			if (coldrag !== null) {
				coldrag = null;
				colclick = Date.now();
			}
		}, true);
		/* Taking hold of a border is not picking the column to sort. */
		document.addEventListener("click", function (e) {
			if (Date.now() - colclick < 350 || colEdge(e) !== null) {
				e.stopPropagation();
				e.preventDefault();
			}
		}, true);
		document.addEventListener("dblclick", function (e) {
			var th = colEdge(e);

			if (th === null)
				return;
			delete colw[colKey(th)];
			arcColsApply(document);
			e.stopPropagation();
			e.preventDefault();
		}, true);

		document.addEventListener("wheel", function (e) {
			var svg = e.target.closest ? e.target.closest(
			    "svg[data-wheel]") : null, m, p;

			if (svg === null || !(m = svg.getScreenCTM()))
				return;
			e.preventDefault();
			p = new DOMPoint(e.clientX, e.clientY)
			    .matrixTransform(m.inverse());
			act(svg.dataset.wheel, "", e.deltaY + "," +
			    p.x.toFixed(1) + "," + p.y.toFixed(1));
		}, { passive: false });
		window.addEventListener("resize", function () {
			act("resize", "", "");
			if (typeof arcCards === "function")
				arcCards(document.body);
		});

		/*
		 * The parts of the page are resized by dragging a handle
		 * (.resizer, data-resize): the tree, the activity dock, the
		 * list of tasks in it, and the service drawer.  A size is a
		 * custom property on the root element, kept per browser;
		 * a double click goes back to the usual one.
		 */
		var sizes = {}, resizing = null, root = document.documentElement;
		var props = { rail: "--rail-w", dock: "--dock-h", ops: "--ops-w",
		    drawer: "--drawer-w" };

		function applySizes() {
			Object.keys(props).forEach(function (k) {
				if (typeof sizes[k] === "number")
					root.style.setProperty(props[k],
					    sizes[k] + "px");
				else
					root.style.removeProperty(props[k]);
			});
		}
		function saveSizes() {
			try {
				localStorage.setItem("arc_sizes",
				    JSON.stringify(sizes));
			} catch (e) {
			}
			/* The tree fits its jails to the room it has. */
			act("resize", "", "");
		}
		function clamp(v, lo, hi) {
			return (Math.round(Math.max(lo, Math.min(hi, v))));
		}
		try {
			sizes = JSON.parse(localStorage.getItem("arc_sizes")) || {};
		} catch (e) {
			sizes = {};
		}
		applySizes();
		document.addEventListener("pointerdown", function (e) {
			var t = e.target.closest ? e.target.closest(".resizer") :
			    null;

			if (t === null || e.button > 0)
				return;
			e.preventDefault();
			resizing = t.dataset.resize;
			root.classList.add("resizing");
		});
		window.addEventListener("pointermove", function (e) {
			var r, w = window.innerWidth, h = window.innerHeight, el;

			if (resizing === null)
				return;
			if (resizing === "rail") {
				r = document.getElementById("body")
				    .getBoundingClientRect();
				sizes.rail = clamp(e.clientX - r.left, 150, w * .6);
			} else if (resizing === "drawer") {
				r = document.getElementById("body")
				    .getBoundingClientRect();
				sizes.drawer = clamp(r.right - e.clientX, 280,
				    w * .7);
			} else if (resizing === "ops") {
				el = document.querySelector(".dock-body");
				if (el === null)
					return;
				r = el.getBoundingClientRect();
				sizes.ops = clamp(e.clientX - r.left, 140,
				    r.width * .7);
			} else if (resizing === "dock") {
				el = document.querySelector(".dock-body");
				if (el === null)
					return;
				r = el.getBoundingClientRect();
				sizes.dock = clamp(r.bottom - e.clientY, 120,
				    h - 160);
			}
			applySizes();
		});
		function endDrag() {
			if (resizing === null)
				return;
			resizing = null;
			root.classList.remove("resizing");
			saveSizes();
		}
		window.addEventListener("pointerup", endDrag);
		window.addEventListener("pointercancel", endDrag);
		document.addEventListener("dblclick", function (e) {
			var t = e.target.closest ? e.target.closest(".resizer") :
			    null;

			if (t === null)
				return;
			delete sizes[t.dataset.resize];
			applySizes();
			saveSizes();
		});
		window.addEventListener("online", function () {
			Module._arc_on_net(1);
		});
		window.addEventListener("offline", function () {
			Module._arc_on_net(0);
		});
		document.addEventListener("visibilitychange", function () {
			Module._arc_on_visible(document.hidden ? 0 : 1);
		});
		Module._arc_on_net(navigator.onLine ? 1 : 0);
	},

	/*
	 * HTTP to the console's own API.  status 0 means the request did
	 * not get an answer at all.
	 */
	/*
	 * Load the page again, as the one a newer console serves.  The
	 * service worker is asked for its update first and given a moment
	 * to take over, or the reload would get the old shell from its
	 * cache.
	 */
	arc_reload: function () {
		var done = false;

		function go() {
			if (!done) {
				done = true;
				location.reload();
			}
		}
		setTimeout(go, 6000);
		if (!navigator.serviceWorker ||
		    !navigator.serviceWorker.getRegistration) {
			go();
			return;
		}
		navigator.serviceWorker.addEventListener("controllerchange",
		    go);
		navigator.serviceWorker.getRegistration().then(function (r) {
			if (!r)
				go();
			else
				r.update().then(function () {
					/* Nothing newer to install. */
					if (!r.installing && !r.waiting)
						go();
				}).catch(go);
		}).catch(go);
	},

	/*
	 * Web Push: this browser subscribes with its push service and
	 * gives the console the address and keys, so that tasks ending in
	 * another browser are told here; and tasks ending here are told to
	 * the others.  Only with notifications allowed.
	 */
	$arcPush: { endpoint: "" },
	$arcPushPost: function (path, body) {
		return (fetch(path, {
			method: "POST",
			credentials: "same-origin",
			headers: { "Content-Type": "application/json",
			    "X-Arcana": "1" },
			body: JSON.stringify(body)
		}));
	},
	arc_push_sync__deps: ["$arcPush", "$arcPushPost", "$arcStr"],
	arc_push_sync: function () {
		var key;

		/* Turned off in this console: nothing is subscribed. */
		try {
			if (localStorage.getItem("arc_notify") === "off")
				return;
		} catch (e) {
		}

		function bytes(b64) {
			var s = atob(b64.replace(/-/g, "+").replace(/_/g, "/") +
			    "===".slice((b64.length + 3) % 4)), a, i;

			a = new Uint8Array(s.length);
			for (i = 0; i < s.length; i++)
				a[i] = s.charCodeAt(i);
			return (a);
		}
		function device() {
			var ua = navigator.userAgent, os, br;

			os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(
			    ua) ? "iOS" : /FreeBSD/.test(ua) ? "FreeBSD" :
			    /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ?
			    "macOS" : /Linux/.test(ua) ? "Linux" : "a device";
			br = /Firefox/.test(ua) ? "Firefox" : /Edg\//.test(ua) ?
			    "Edge" : /Chrome/.test(ua) ? "Chrome" :
			    /Safari/.test(ua) ? "Safari" : "a browser";
			return (br + " on " + os);
		}
		if (!("serviceWorker" in navigator) || !("PushManager" in
		    window) || !("Notification" in window) ||
		    Notification.permission !== "granted")
			return;
		fetch("/api/push", { credentials: "same-origin" })
		    .then(function (r) {
			return (r.ok ? r.json() : null);
		}).then(function (j) {
			if (!j || !j.public_key)
				return (null);
			key = j.public_key;
			return (navigator.serviceWorker.ready);
		}).then(function (reg) {
			if (!reg)
				return (null);
			return (reg.pushManager.getSubscription().then(
			    function (sub) {
				return (sub || reg.pushManager.subscribe({
					userVisibleOnly: true,
					applicationServerKey: bytes(key)
				}));
			}));
		}).then(function (sub) {
			var j;

			if (!sub)
				return (null);
			j = sub.toJSON();
			arcPush.endpoint = j.endpoint;
			return (arcPushPost("/api/push/subscribe", {
				endpoint: j.endpoint,
				p256dh: j.keys.p256dh,
				auth: j.keys.auth,
				name: device()
			}));
		}).then(function () {
			Module._arc_on_action(arcStr("push-changed"),
			    arcStr(""), arcStr(""));
		}).catch(function (e) {
			console.warn("push:", e);
		});
	},
	arc_push_send__deps: ["$arcPush", "$arcPushPost", "$UTF8ToString"],
	arc_push_send: function (titlep, bodyp) {
		arcPushPost("/api/push/send", {
			title: UTF8ToString(titlep),
			body: UTF8ToString(bodyp),
			except: arcPush.endpoint
		}).catch(function () {
		});
	},
	arc_push_remove__deps: ["$arcPush", "$arcPushPost", "$UTF8ToString",
	    "$arcStr"],
	arc_push_remove: function (endpointp) {
		var endpoint = UTF8ToString(endpointp);

		function done() {
			Module._arc_on_action(arcStr("push-changed"),
			    arcStr(""), arcStr(""));
		}
		arcPushPost("/api/push/unsubscribe", { endpoint: endpoint })
		    .then(done).catch(done);
		/* This browser itself: its subscription goes too. */
		if (endpoint === arcPush.endpoint && navigator.serviceWorker) {
			arcPush.endpoint = "";
			navigator.serviceWorker.ready.then(function (reg) {
				return (reg.pushManager.getSubscription());
			}).then(function (sub) {
				if (sub)
					sub.unsubscribe();
			}).catch(function () {
			});
		}
	},
	/*
	 * This browser's own subscription let go of, on the console and in
	 * the browser: nothing is pushed to it while it is off.
	 */
	arc_push_off__deps: ["$arcPush", "$arcPushPost", "$arcStr"],
	arc_push_off: function () {
		function done() {
			Module._arc_on_action(arcStr("push-changed"),
			    arcStr(""), arcStr(""));
		}

		arcPush.endpoint = "";
		if (!navigator.serviceWorker)
			return;
		navigator.serviceWorker.ready.then(function (reg) {
			return (reg.pushManager.getSubscription());
		}).then(function (sub) {
			if (!sub)
				return (null);
			return (arcPushPost("/api/push/unsubscribe", {
				endpoint: sub.endpoint
			}).then(function () {
				return (sub.unsubscribe());
			}));
		}).then(done).catch(done);
	},
	arc_push_here__deps: ["$arcPush", "$arcStr"],
	arc_push_here: function () {
		return (arcStr(arcPush.endpoint));
	},

	/* A text kept in this browser under a name; "" when there is none. */
	arc_store_get__deps: ["$arcStr", "$UTF8ToString"],
	arc_store_get: function (keyp) {
		var v = "";

		try {
			v = localStorage.getItem(UTF8ToString(keyp)) || "";
		} catch (e) {
		}
		return (arcStr(v));
	},
	arc_store_set__deps: ["$UTF8ToString"],
	arc_store_set: function (keyp, valuep) {
		try {
			localStorage.setItem(UTF8ToString(keyp),
			    UTF8ToString(valuep));
		} catch (e) {
		}
	},

	/*
	 * The theme, kept per browser: a name the stylesheet knows, or
	 * none for the default.  The bar of the installed app follows the
	 * page's background.
	 */
	arc_theme_get__deps: ["$arcStr"],
	arc_theme_get: function () {
		return (arcStr(document.documentElement.dataset.theme || ""));
	},
	/* A text saved as a file: a document as JSON, to keep. */
	arc_save_text__deps: ["$UTF8ToString"],
	arc_save_text: function (namep, typep, textp) {
		var url, a;

		/* The last one, for whoever checks what was saved. */
		window.arcSaved = { name: UTF8ToString(namep), type:
		    UTF8ToString(typep), text: UTF8ToString(textp) };
		url = URL.createObjectURL(new Blob([window.arcSaved.text], {
		    type: window.arcSaved.type }));
		a = document.createElement("a");
		a.href = url;
		a.download = UTF8ToString(namep);
		document.body.appendChild(a);
		a.click();
		a.remove();
		setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
	},
	/*
	 * A drawing of the page saved as a PNG picture, as it is shown but
	 * in the light theme (paper), whatever the page wears: a copy of the
	 * SVG with every element's computed style written on it (the page's
	 * classes and variables do not travel with it), drawn twice its size
	 * on a canvas over the map's background.  The theme is put on for
	 * the reading alone, transitions off, and taken off again.
	 */
	arc_svg_png__deps: ["$UTF8ToString"],
	arc_svg_png: function (selp, namep) {
		var svg = document.querySelector(UTF8ToString(selp)),
		    name = UTF8ToString(namep), props = ["fill", "fill-opacity",
		    "stroke", "stroke-width", "stroke-dasharray", "stroke-opacity",
		    "stroke-linecap", "stroke-linejoin", "stroke-dashoffset",
		    "paint-order", "opacity", "font-family", "font-style",
		    "font-size", "font-weight", "text-anchor", "letter-spacing",
		    "dominant-baseline", "visibility", "display"],
		    clone, src, dst, i, cs, r, w, h, bg, el, img, root, old, calm;

		if (svg === null)
			return;
		root = document.documentElement;
		old = root.getAttribute("data-theme");
		calm = document.createElement("style");
		calm.textContent = "*, *::before, *::after { transition: none " +
		    "!important; animation: none !important; }";
		document.head.appendChild(calm);
		root.setAttribute("data-theme", "paper");
		clone = svg.cloneNode(true);
		src = [svg].concat(Array.prototype.slice.call(
		    svg.querySelectorAll("*")));
		dst = [clone].concat(Array.prototype.slice.call(
		    clone.querySelectorAll("*")));
		for (i = 0; i < src.length && i < dst.length; i++) {
			cs = getComputedStyle(src[i]);
			dst[i].setAttribute("style", props.map(function (p) {
				return (p + ":" + cs.getPropertyValue(p));
			}).join(";"));
		}
		r = svg.getBoundingClientRect();
		w = Math.max(1, Math.round(r.width * 2));
		h = Math.max(1, Math.round(r.height * 2));
		clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
		clone.setAttribute("width", w);
		clone.setAttribute("height", h);
		bg = "";
		for (el = svg; el !== null && (bg === "" || bg === "transparent" ||
		    bg === "rgba(0, 0, 0, 0)"); el = el.parentElement)
			bg = getComputedStyle(el).backgroundColor;
		if (old === null)
			root.removeAttribute("data-theme");
		else
			root.setAttribute("data-theme", old);
		calm.remove();
		img = new Image();
		img.onload = function () {
			var c = document.createElement("canvas"),
			    x = c.getContext("2d");

			c.width = w;
			c.height = h;
			x.fillStyle = bg || "#f3f5f7";
			x.fillRect(0, 0, w, h);
			x.drawImage(img, 0, 0, w, h);
			c.toBlob(function (b) {
				var url, a;

				/* The last one, for whoever checks what was
				 * saved. */
				window.arcSaved = { name: name, type: "image/png",
				    size: b.size, width: w, height: h };
				/* And the picture itself, for a test to show. */
				(function (s) {
					var fr = new FileReader();

					fr.onload = function () { s.url = fr.result; };
					fr.readAsDataURL(b);
				})(window.arcSaved);
				url = URL.createObjectURL(b);
				a = document.createElement("a");
				a.href = url;
				a.download = name;
				document.body.appendChild(a);
				a.click();
				a.remove();
				setTimeout(function () { URL.revokeObjectURL(url); },
				    10000);
			}, "image/png");
		};
		img.onerror = function () {
			window.arcSaved = { name: name, error: true };
		};
		img.src = "data:image/svg+xml;charset=utf-8," +
		    encodeURIComponent(new XMLSerializer().serializeToString(clone));
	},
	/* A file made of base64, saved: a capture's pcap. */
	arc_save_b64__deps: ["$UTF8ToString"],
	arc_save_b64: function (namep, typep, b64p) {
		var bin = atob(UTF8ToString(b64p)), bytes = new Uint8Array(
		    bin.length), i, a, url;

		for (i = 0; i < bin.length; i++)
			bytes[i] = bin.charCodeAt(i);
		url = URL.createObjectURL(new Blob([bytes], {
		    type: UTF8ToString(typep) }));
		a = document.createElement("a");
		a.href = url;
		a.download = UTF8ToString(namep);
		document.body.appendChild(a);
		a.click();
		a.remove();
		setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
	},
	arc_theme_set__deps: ["$UTF8ToString", "$arcPlug"],
	arc_theme_set: function (namep) {
		var name = UTF8ToString(namep), meta;

		if (name === "")
			delete document.documentElement.dataset.theme;
		else
			document.documentElement.dataset.theme = name;
		/* Glow and capitals, or the plain rules (fx.js). */
		document.documentElement.classList.toggle("neon",
		    /^(tron|amber|matrix|synth)$/.test(name));
		try {
			if (name === "")
				localStorage.removeItem("arc_theme");
			else
				localStorage.setItem("arc_theme", name);
		} catch (e) {
		}
		meta = document.querySelector("meta[name=theme-color]");
		if (meta)
			meta.content = getComputedStyle(document.documentElement)
			    .getPropertyValue("--bg").trim() || meta.content;
		Promise.resolve().then(function () {
			arcPlug.emit("theme", { theme: name });
		});
	},

	/* The requests in flight that can be given up: id to its abort. */
	$arcAborts: {},
	arc_http_abort__deps: ["$arcAborts"],
	arc_http_abort: function (id) {
		if (arcAborts[id]) {
			arcAborts[id].gaveUp = true;
			arcAborts[id].abort();
		}
	},

	arc_http__deps: ["$arcAborts", "$arcStr", "$UTF8ToString"],
	arc_http: function (id, methodp, urlp, bodyp) {
		var method = UTF8ToString(methodp), body = null, opts;
		var ctl = new AbortController(), url = UTF8ToString(urlp);

		if (bodyp !== 0)
			body = UTF8ToString(bodyp);
		/* A YANG Patch (RFC 8072) is its own media type. */
		opts = {
			method: method,
			credentials: "same-origin",
			cache: "no-store",
			headers: { "Content-Type": body !== null &&
			    body.indexOf('{"ietf-yang-patch:yang-patch"') === 0 ?
			    "application/yang-patch+json" : "application/json",
			    "X-Arcana": "1" },
			signal: ctl.signal
		};
		if (body !== null)
			opts.body = body;
		arcAborts[id] = ctl;
		/*
		 * A 408 is the server's answer to a connection it found
		 * idle, not to this request: the browser had opened the
		 * connection ahead of time, and the request went out on it
		 * as the server gave up waiting.  Nothing was done with the
		 * request, so it is sent again, on a connection of its own.
		 *
		 * A 502, 503 or 504 whose body is not the console's own
		 * JSON came from a proxy in front of it, which could not
		 * reach the console at that moment: while it starts again,
		 * or is busy.  A question is asked again a few times, ever
		 * later, before a host is said not to answer; what would
		 * change something is not, since it may have arrived.
		 */
		(function send(tries) {
			fetch(url, opts).then(function (r) {
				if (r.status === 408 && tries < 3) {
					setTimeout(function () {
						send(tries + 1);
					}, 150 * (tries + 1));
					return (null);
				}
				return (r.text().then(function (t) {
					if (method === "GET" && r.status >= 502 &&
					    r.status <= 504 && t.charAt(0) !==
					    "{" && tries < 4 && !ctl.gaveUp) {
						setTimeout(function () {
							send(tries + 1);
						}, 400 * (tries + 1) * (tries + 1));
						return;
					}
					delete arcAborts[id];
					Module._arc_on_http(id, r.status,
					    arcStr(t));
				}));
			}).catch(function (err) {
				delete arcAborts[id];
				Module._arc_on_http(id, 0, arcStr(ctl.gaveUp ?
				    "cancelled" : String(err)));
			});
		})(0);
	},

	/*
	 * WebAuthn.  options is what the console sent (binary fields in
	 * base64url); the result goes back the same way, with the public
	 * key as SubjectPublicKeyInfo so the server needs no CBOR.
	 */
	arc_webauthn__deps: ["$UTF8ToString", "$arcStr", "$arcB64"],
	arc_webauthn: function (id, create, optsp) {
		var o, pk, p;

		function done(ok, v) {
			Module._arc_on_webauthn(id, ok, arcStr(v));
		}
		if (!window.PublicKeyCredential) {
			done(0, "this browser has no WebAuthn");
			return;
		}
		o = JSON.parse(UTF8ToString(optsp));
		pk = o.publicKey;
		pk.challenge = arcB64.dec(pk.challenge);
		if (pk.user)
			pk.user.id = arcB64.dec(pk.user.id);
		(pk.excludeCredentials || []).forEach(function (c) {
			c.id = arcB64.dec(c.id);
		});
		(pk.allowCredentials || []).forEach(function (c) {
			c.id = arcB64.dec(c.id);
		});
		p = create ? navigator.credentials.create({ publicKey: pk }) :
		    navigator.credentials.get({ publicKey: pk });
		p.then(function (cred) {
			var r = cred.response, out = {
				id: cred.id,
				clientDataJSON: arcB64.enc(r.clientDataJSON)
			};

			if (create) {
				out.authenticatorData =
				    arcB64.enc(r.getAuthenticatorData());
				out.publicKey = arcB64.enc(r.getPublicKey());
				out.publicKeyAlgorithm =
				    r.getPublicKeyAlgorithm();
				out.transports = r.getTransports ?
				    r.getTransports() : [];
			} else {
				out.authenticatorData =
				    arcB64.enc(r.authenticatorData);
				out.signature = arcB64.enc(r.signature);
			}
			done(1, JSON.stringify(out));
		}).catch(function (err) {
			done(0, err && err.name === "NotAllowedError" ?
			    "cancelled or timed out" : String(err));
		});
	},

	/*
	 * The service worker keeps the shell for when there is no network.
	 * A newer shell on the console is looked for whenever the page
	 * comes back into view, which for an installed app is every time it
	 * is opened, and now and then while it stays open; when a newer
	 * worker has taken over, the page loads itself again as the new
	 * one.  Without that an installed app, which is resumed rather
	 * than loaded, would stay what it was when it was installed.
	 */
	arc_sw_register: function () {
		var had, reloading = false;

		if (!("serviceWorker" in navigator))
			return;
		had = !!navigator.serviceWorker.controller;
		navigator.serviceWorker.addEventListener("controllerchange",
		    function () {
			/* The first worker of all changes nothing shown. */
			if (had && !reloading) {
				reloading = true;
				location.reload();
			}
			had = true;
		});
		navigator.serviceWorker.register("sw.js",
		    { updateViaCache: "none" }).then(function (reg) {
			function check() {
				reg.update().catch(function () {});
			}
			document.addEventListener("visibilitychange",
			    function () {
				if (!document.hidden)
					check();
			});
			setInterval(check, 30 * 60 * 1000);
		}).catch(function (e) {
			console.warn("service worker:", e);
		});
	},

	arc_now: function () {
		return (Date.now());
	},

	/* An element over the whole screen (the Fullscreen API), or the
	 * screen given back; what the browser refuses stays as it is. */
	arc_fullscreen__deps: ["$UTF8ToString"],
	arc_fullscreen: function (selp, on) {
		var el = document.querySelector(UTF8ToString(selp));

		try {
			if (on && el !== null && el.requestFullscreen)
				el.requestFullscreen().catch(function () {});
			else if (!on && document.fullscreenElement)
				document.exitFullscreen().catch(function () {});
		} catch (e) {
		}
	},

	/* The room the fleet's map has on the page, 0 when not drawn yet. */
	arc_map_w: function () {
		var el = document.querySelector(".netmap:not(.ngmap) " +
		    "> .map-wrap");

		return (el === null ? 0 : el.clientWidth);
	},
	arc_map_h: function () {
		var el = document.querySelector(".netmap:not(.ngmap) " +
		    "> .map-wrap");

		return (el === null ? 0 : el.clientHeight);
	},

	/*
	 * What comes in parts: one WebSocket to the console, opened when
	 * first needed and again when it went.  What is asked while it is
	 * not open yet waits; every message goes to arc_on_stream(), and
	 * so does {"closed": true} when the socket is lost.
	 */
	$arcStream: { ws: null, wait: [] },
	arc_stream_send__deps: ["$arcStream", "$arcStr", "$UTF8ToString"],
	arc_stream_send: function (textp) {
		var text = UTF8ToString(textp), st = arcStream, ws;

		if (st.ws !== null && st.ws.readyState === 1) {
			st.ws.send(text);
			return;
		}
		st.wait.push(text);
		if (st.ws !== null && st.ws.readyState === 0)
			return;
		try {
			ws = new WebSocket((location.protocol === "https:" ?
			    "wss://" : "ws://") + location.host + "/api/stream");
		} catch (e) {
			st.wait = [];
			Module._arc_on_stream(arcStr("{\"closed\":true}"));
			return;
		}
		st.ws = ws;
		ws.onopen = function () {
			var q = st.wait;

			st.wait = [];
			q.forEach(function (t) { ws.send(t); });
		};
		ws.onmessage = function (e) {
			if (typeof e.data === "string")
				Module._arc_on_stream(arcStr(e.data));
		};
		ws.onclose = function () {
			if (st.ws === ws)
				st.ws = null;
			st.wait = [];
			Module._arc_on_stream(arcStr("{\"closed\":true}"));
		};
	},

	/* Is the window as narrow as a phone held upright? */
	arc_narrow: function () {
		return (window.innerWidth <= 620 ? 1 : 0);
	},

	/*
	 * The page's address, #/hosts/<id>/<tab> and the like (main.c):
	 * read when the page opens, written as what is shown changes, a
	 * new history entry (push) or in place.
	 */
	arc_loc_get__deps: ["$arcStr"],
	arc_loc_get: function () {
		return (arcStr(location.hash));
	},
	arc_loc_set__deps: ["$UTF8ToString", "$arcPlug"],
	arc_loc_set: function (p, push) {
		var h = UTF8ToString(p);

		if (location.hash === h)
			return;
		try {
			if (push)
				history.pushState(null, "", h);
			else
				history.replaceState(null, "", h);
		} catch (e) {
		}
		Promise.resolve().then(function () {
			arcPlug.emit("route", { hash: h });
		});
	},

	arc_title__deps: ["$UTF8ToString"],
	arc_title: function (p) {
		document.title = UTF8ToString(p);
	},

	/*
	 * What is folded on the page, per browser: the boxes shut by their
	 * heads (view.c's box_shut()).
	 */
	$arcOpen: function () {
		try {
			var v = JSON.parse(localStorage.getItem("arc_open"));

			return (Array.isArray(v) ? v : []);
		} catch (e) {
			return ([]);
		}
	},
	arc_open_get__deps: ["$arcOpen", "$UTF8ToString"],
	arc_open_get: function (idp) {
		return (arcOpen().indexOf(UTF8ToString(idp)) !== -1 ? 1 : 0);
	},
	arc_open_set__deps: ["$arcOpen", "$UTF8ToString"],
	arc_open_set: function (idp, on) {
		var id = UTF8ToString(idp), v = arcOpen().filter(function (x) {
			return (x !== id);
		});

		if (on)
			v.push(id);
		try {
			localStorage.setItem("arc_open", JSON.stringify(v));
		} catch (e) {
		}
	},

	/*
	 * Changes are held in the queue until sent, unless this browser
	 * turned that off: a slip of the finger changes nothing by itself.
	 */
	arc_queue_get: function () {
		try {
			return (localStorage.getItem("arc_queue") !== "0" ? 1 : 0);
		} catch (e) {
			return (1);
		}
	},
	arc_queue_set: function (on) {
		try {
			localStorage.setItem("arc_queue", on ? "1" : "0");
		} catch (e) {
		}
	},

	/*
	 * The map's canvas: 0 when there is none; 1 when there is, 2 more
	 * when the page has just made it (a device or context is to be
	 * made on it), 4 more when motion is not wanted, 8 more when the
	 * browser has WebGPU to ask.
	 */
	arc_gl_probe: function () {
		var c = document.getElementById("map-gl"), s;

		if (c === null)
			return (0);
		s = 1;
		if (!c._arcSeen) {
			c._arcSeen = true;
			s |= 2;
		}
		if (window.matchMedia && window.matchMedia(
		    "(prefers-reduced-motion: reduce)").matches)
			s |= 4;
		if (navigator.gpu)
			s |= 8;
		return (s);
	},
	/* What it drew, for whoever looks (the tests): whether a backend
	 * is there and which, the points of the last frame, the links with
	 * traffic, the tunnels whose probes are drawn, the lines moving
	 * with the hand, and how WebGPU answered (0 not asked, 1 asked, 2 a
	 * device, -1 none). */
	arc_gl_report: function (ok, points, flows, probes, wires, be, gpu,
	    fails, opens, losts) {
		window.arcGl = { ok: ok !== 0, points: points, flows: flows,
		    probes: probes, wires: wires, backend: be === 2 ? "webgpu" :
		    be === 1 ? "webgl2" : "none", gpu: gpu, fails: fails,
		    opens: opens, losts: losts };
	},
	/* The map's canvas swapped for a fresh one, the same in every
	 * attribute, for a context of another kind than it had. */
	arc_gl_fresh: function () {
		var c = document.getElementById("map-gl"), n;

		if (c === null)
			return;
		n = c.cloneNode(false);
		n._arcSeen = true;
		c.replaceWith(n);
	},
	/* A word from the layer for whoever looks: why a device went. */
	arc_gl_note__deps: ["$UTF8ToString"],
	arc_gl_note: function (p) {
		window.arcGlNote = UTF8ToString(p);
	},
	/* The map's drawing and canvas moved as one by the browser, tx and
	 * ty pixels and r times larger about the middle, while the hand
	 * pans or the wheel zooms; the page draws the map anew when the
	 * hand rests, and the transform goes with that redraw. */
	arc_map_view: function (tx, ty, r) {
		var t = tx === 0 && ty === 0 && r === 1 ? "" : "translate(" +
		    tx.toFixed(1) + "px," + ty.toFixed(1) + "px) scale(" +
		    r.toFixed(4) + ")", s = document.querySelector("svg.topo"),
		    c = document.getElementById("map-gl");

		if (s !== null)
			s.style.transform = t;
		if (c !== null)
			c.style.transform = t;
	},
	/* A colour the theme defines (--name), as 0xrrggbb, or -1. */
	arc_css_rgb__deps: ["$UTF8ToString"],
	arc_css_rgb: function (namep) {
		var v = getComputedStyle(document.documentElement)
		    .getPropertyValue(UTF8ToString(namep)).trim(), m;

		if ((m = /^#([0-9a-f]{6})$/i.exec(v)) !== null)
			return (parseInt(m[1], 16));
		if ((m = /^#([0-9a-f]{3})$/i.exec(v)) !== null)
			return (parseInt(m[1].replace(/(.)/g, "$1$1"), 16));
		if ((m = /^rgba?\(\s*(\d+)[ ,]+(\d+)[ ,]+(\d+)/.exec(v)) !==
		    null)
			return ((+m[1] << 16) | (+m[2] << 8) | +m[3]);
		return (-1);
	},

	/* Visual effects on or off, kept per browser; index.html applies
	 * the class before the first paint. */
	arc_fx_get: function () {
		try {
			return (localStorage.getItem("arc_fx") !== "0" ? 1 : 0);
		} catch (e) {
			return (1);
		}
	},
	arc_fx_set: function (on) {
		try {
			localStorage.setItem("arc_fx", on ? "1" : "0");
		} catch (e) {
		}
		document.documentElement.classList.toggle("fx", on !== 0);
	},

	/*
	 * Installing the console as an app, offered on a phone or tablet
	 * that has it open in the browser.  Chromium hands over an event to
	 * prompt with, which can come before the program has started: the
	 * listeners are set when this file loads.  State: 0 nothing to
	 * offer (installed, dismissed, or not a mobile browser), 1 a prompt
	 * is ready, 2 Safari on iOS, where it is done from the Share menu,
	 * 3 another mobile browser, where it is in the browser's menu.
	 */
	$arcInstall: { ev: null, ready: false },
	$arcInstall__deps: ["$arcStr"],
	$arcInstall__postset: "(function () {" +
	    "function tell() {" +
	    "if (arcInstall.ready) Module._arc_on_action(" +
	    "arcStr('install-changed'), arcStr(''), arcStr('')); }" +
	    "window.addEventListener('beforeinstallprompt', function (e) {" +
	    "e.preventDefault(); arcInstall.ev = e; tell(); });" +
	    "window.addEventListener('appinstalled', function () {" +
	    "arcInstall.ev = null; arcInstall.done = true; tell(); });" +
	    "})();",
	arc_install_state__deps: ["$arcInstall"],
	arc_install_state: function () {
		var ua = navigator.userAgent, ios;

		arcInstall.ready = true;
		if (arcInstall.done || navigator.standalone === true ||
		    matchMedia("(display-mode: standalone)").matches)
			return (0);
		try {
			if (localStorage.getItem("arc_install") === "0")
				return (0);
		} catch (e) {
		}
		/* An iPad says it is a Mac, but a Mac has no touch screen. */
		ios = /iPhone|iPad|iPod/.test(ua) ||
		    (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
		if (!ios && !/Android/.test(ua) &&
		    !(navigator.userAgentData && navigator.userAgentData.mobile))
			return (0);
		if (arcInstall.ev !== null)
			return (1);
		if (ios)
			return (2);
		return (/Firefox/.test(ua) ? 3 : 0);
	},
	arc_install_prompt__deps: ["$arcInstall", "$arcStr"],
	arc_install_prompt: function () {
		var ev = arcInstall.ev;

		if (ev === null)
			return;
		/* The event prompts once; the browser sends another when
		 * the app can be offered again. */
		arcInstall.ev = null;
		ev.prompt();
		ev.userChoice.then(function (c) {
			if (c && c.outcome === "accepted")
				arcInstall.done = true;
		}).catch(function () {
		}).then(function () {
			Module._arc_on_action(arcStr("install-changed"),
			    arcStr(""), arcStr(""));
		});
	},
	arc_install_dismiss: function () {
		try {
			localStorage.setItem("arc_install", "0");
		} catch (e) {
		}
	},

	/*
	 * Desktop notifications for tasks that took long: 0 not asked yet,
	 * 1 granted, 2 denied, 3 the browser has none.  Shown through the
	 * service worker where there is one, as installed apps need.
	 */
	arc_notify_state: function () {
		if (!("Notification" in window))
			return (3);
		return (Notification.permission === "granted" ? 1 :
		    Notification.permission === "denied" ? 2 : 0);
	},
	arc_notify_ask__deps: ["$arcStr"],
	arc_notify_ask: function () {
		if (!("Notification" in window))
			return;
		Notification.requestPermission().then(function () {
			Module._arc_on_action(arcStr("notify-changed"),
			    arcStr(""), arcStr(""));
		});
	},
	arc_notify__deps: ["$UTF8ToString"],
	arc_notify: function (titlep, bodyp) {
		var title = UTF8ToString(titlep), opts = {
			body: UTF8ToString(bodyp),
			icon: "icons/icon-192.png",
			tag: "arcana"
		};

		if (!("Notification" in window) ||
		    Notification.permission !== "granted")
			return;
		try {
			if (localStorage.getItem("arc_notify") === "off")
				return;
		} catch (e) {
		}
		if (navigator.serviceWorker && navigator.serviceWorker.ready)
			navigator.serviceWorker.ready.then(function (r) {
				return (r.showNotification(title, opts));
			}).catch(function () {
				new Notification(title, opts);
			});
		else
			new Notification(title, opts);
	},

	arc_origin__deps: ["$arcStr"],
	arc_origin: function () {
		return (arcStr(location.origin));
	},

	arc_hostname__deps: ["$arcStr"],
	arc_hostname: function () {
		return (arcStr(location.host));
	}
});
