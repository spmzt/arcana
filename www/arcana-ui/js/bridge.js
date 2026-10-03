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
			/* Keep the field being typed in; otherwise let
			 * morphdom walk: isEqualNode() on every node costs
			 * more than the walk, in Firefox several times. */
			onBeforeElUpdated: function (from, to) {
				return (!(from === document.activeElement &&
				    (from.tagName === "INPUT" ||
				    from.tagName === "TEXTAREA" ||
				    from.tagName === "SELECT")));
			}
		});
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
	arc_http__deps: ["$UTF8ToString", "$arcStr"],
	arc_http: function (id, methodp, urlp, bodyp) {
		var method = UTF8ToString(methodp), body = null, opts;

		if (bodyp !== 0)
			body = UTF8ToString(bodyp);
		opts = {
			method: method,
			credentials: "same-origin",
			cache: "no-store",
			headers: { "Content-Type": "application/json",
			    "X-Arcana": "1" }
		};
		if (body !== null)
			opts.body = body;
		fetch(UTF8ToString(urlp), opts).then(function (r) {
			return (r.text().then(function (t) {
				Module._arc_on_http(id, r.status, arcStr(t));
			}));
		}).catch(function (err) {
			Module._arc_on_http(id, 0, arcStr(String(err)));
		});
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

	arc_sw_register: function () {
		if ("serviceWorker" in navigator)
			navigator.serviceWorker.register("sw.js")
			    .catch(function (e) {
				console.warn("service worker:", e);
			});
	},

	arc_now: function () {
		return (Date.now());
	},

	arc_title__deps: ["$UTF8ToString"],
	arc_title: function (p) {
		document.title = UTF8ToString(p);
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
