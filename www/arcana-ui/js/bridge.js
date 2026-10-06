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
			onBeforeElUpdated: function (from, to) {
				var tag = from.tagName, i, was, now;

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
	arc_events_init__deps: ["$arcStr"],
	arc_events_init: function () {
		function act(name, arg, value) {
			var a = arcStr(name), b = arcStr(arg), c = arcStr(value);

			Module._arc_on_action(a, b, c);
		}

		document.addEventListener("click", function (e) {
			var t = e.target.closest("[data-act]");

			if (t === null || t.disabled)
				return;
			if (t.tagName === "A" || t.tagName === "BUTTON")
				e.preventDefault();
			act(t.dataset.act, t.dataset.arg || "",
			    t.dataset.value || "");
		});
		document.addEventListener("submit", function (e) {
			var f = e.target, o = {}, i, el;

			e.preventDefault();
			o.__submit = e.submitter && e.submitter.value ?
			    e.submitter.value : "";
			for (i = 0; i < f.elements.length; i++) {
				el = f.elements[i];
				if (!el.name)
					continue;
				o[el.name] = el.type === "checkbox" ?
				    el.checked : el.value;
			}
			act("submit:" + (f.dataset.form || f.id), "",
			    JSON.stringify(o));
		});
		document.addEventListener("input", function (e) {
			var t = e.target;

			if (t.dataset && t.dataset.input)
				act("input:" + t.dataset.input, "", t.value);
		});
		document.addEventListener("keydown", function (e) {
			if (e.key === "Escape")
				act("escape", "", "");
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
		document.addEventListener("pointerdown", function (e) {
			var t = e.target.closest ? e.target.closest(
			    "[data-drag]") : null, svg;

			if (t === null || e.button > 0)
				return;
			svg = t.closest("svg");
			if (svg === null)
				return;
			if (drag !== null)
				return;
			drag = { name: t.dataset.drag, arg: t.dataset.arg || "",
			    svg: svg, x: e.clientX, y: e.clientY, moved: false,
			    last: null, frame: 0, id: e.pointerId };
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
				/* Where it was taken hold of, before it moves. */
				drag.moved = true;
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
						drag.svg = document.querySelector(
						    "svg.topo") || drag.svg;
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
				d.svg = document.querySelector("svg.topo") || d.svg;
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
		window.arcCards = function (root) {
			var narrow = window.matchMedia("(max-width: 620px)")
			    .matches, ts, t, ths, labels, rows, tds, i, j, k;

			ts = root.querySelectorAll("table.net");
			for (i = 0; i < ts.length; i++) {
				t = ts[i];
				if (!narrow) {
					t.classList.remove("cards");
					continue;
				}
				t.classList.add("cards");
				ths = t.querySelectorAll("thead th");
				labels = [];
				for (j = 0; j < ths.length; j++)
					labels.push(ths[j].textContent.trim());
				rows = t.querySelectorAll("tbody > tr");
				for (j = 0; j < rows.length; j++) {
					tds = rows[j].children;
					if (tds.length !== labels.length) {
						rows[j].classList.add("whole");
						continue;
					}
					for (k = 0; k < tds.length; k++)
						if (tds[k].dataset.label !==
						    labels[k])
							tds[k].dataset.label =
							    labels[k];
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
	arc_theme_set__deps: ["$UTF8ToString"],
	arc_theme_set: function (namep) {
		var name = UTF8ToString(namep), meta;

		/* The default one, chosen where it is not the default. */
		if (name === "" && window.matchMedia("(max-width: 620px)")
		    .matches)
			name = "tron";
		if (name === "")
			delete document.documentElement.dataset.theme;
		else
			document.documentElement.dataset.theme = name;
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
		opts = {
			method: method,
			credentials: "same-origin",
			cache: "no-store",
			headers: { "Content-Type": "application/json",
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

	arc_title__deps: ["$UTF8ToString"],
	arc_title: function (p) {
		document.title = UTF8ToString(p);
	},

	/*
	 * How many jail rows the tree has room for, besides its other
	 * rows: the free space under the hosts.  -1 before it is drawn.
	 * It depends on the tree's height and on the rows that are always
	 * there, not on the jails shown, so it does not feed on itself.
	 */
	arc_tree_room: function () {
		var tree = document.querySelector(".tree"), leaf, max, h, used;

		if (tree === null)
			return (-1);
		max = parseFloat(getComputedStyle(tree).maxHeight);
		h = isNaN(max) ? tree.clientHeight : max;
		used = 0;
		tree.querySelectorAll(".titem:not(.leaf)").forEach(function (e) {
			used += e.offsetHeight;
		});
		leaf = tree.querySelector(".titem.leaf");
		return (Math.max(0, Math.floor((h - used - 8) /
		    (leaf !== null && leaf.offsetHeight > 0 ?
		    leaf.offsetHeight : 27))));
	},

	/*
	 * The hosts whose jails are shown in the tree, per browser: a host
	 * starts folded, so a long fleet is a short list.
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
