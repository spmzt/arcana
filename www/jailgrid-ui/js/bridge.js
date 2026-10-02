/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Browser APIs for the C application (an Emscripten --js-library).  Only
 * plumbing lives here: the application's logic, state and markup are C.
 *
 * C calls jg_*; the browser calls back into C through the exported
 * jg_on_* functions with strings in the wasm heap, which C frees.
 */

addToLibrary({
	$jgStr__deps: ["$stringToNewUTF8"],
	$jgStr: function (s) {
		return (stringToNewUTF8(s === null || s === undefined ?
		    "" : String(s)));
	},

	$jgB64: {
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
	jg_patch__deps: ["$UTF8ToString"],
	jg_patch: function (idp, htmlp) {
		var el = document.getElementById(UTF8ToString(idp));
		var html = UTF8ToString(htmlp);

		if (el === null)
			return;
		morphdom(el, "<div>" + html + "</div>", {
			childrenOnly: true,
			onBeforeElUpdated: function (from, to) {
				if (from === document.activeElement &&
				    (from.tagName === "INPUT" ||
				    from.tagName === "TEXTAREA" ||
				    from.tagName === "SELECT"))
					return (false);
				return (!from.isEqualNode(to));
			}
		});
	},

	jg_focus__deps: ["$UTF8ToString"],
	jg_focus: function (idp) {
		var el = document.getElementById(UTF8ToString(idp));

		if (el !== null)
			el.focus();
	},

	/*
	 * Events: clicks on [data-act], submitted forms (fields as a JSON
	 * object), typing in [data-input], Escape, network and visibility.
	 */
	jg_events_init__deps: ["$jgStr"],
	jg_events_init: function () {
		function act(name, arg, value) {
			var a = jgStr(name), b = jgStr(arg), c = jgStr(value);

			Module._jg_on_action(a, b, c);
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
			Module._jg_on_net(1);
		});
		window.addEventListener("offline", function () {
			Module._jg_on_net(0);
		});
		document.addEventListener("visibilitychange", function () {
			Module._jg_on_visible(document.hidden ? 0 : 1);
		});
		Module._jg_on_net(navigator.onLine ? 1 : 0);
	},

	/*
	 * HTTP to the console's own API.  status 0 means the request did
	 * not get an answer at all.
	 */
	jg_http__deps: ["$UTF8ToString", "$jgStr"],
	jg_http: function (id, methodp, urlp, bodyp) {
		var method = UTF8ToString(methodp), body = null, opts;

		if (bodyp !== 0)
			body = UTF8ToString(bodyp);
		opts = {
			method: method,
			credentials: "same-origin",
			cache: "no-store",
			headers: { "Content-Type": "application/json",
			    "X-Jailgrid": "1" }
		};
		if (body !== null)
			opts.body = body;
		fetch(UTF8ToString(urlp), opts).then(function (r) {
			return (r.text().then(function (t) {
				Module._jg_on_http(id, r.status, jgStr(t));
			}));
		}).catch(function (err) {
			Module._jg_on_http(id, 0, jgStr(String(err)));
		});
	},

	/*
	 * WebAuthn.  options is what the console sent (binary fields in
	 * base64url); the result goes back the same way, with the public
	 * key as SubjectPublicKeyInfo so the server needs no CBOR.
	 */
	jg_webauthn__deps: ["$UTF8ToString", "$jgStr", "$jgB64"],
	jg_webauthn: function (id, create, optsp) {
		var o, pk, p;

		function done(ok, v) {
			Module._jg_on_webauthn(id, ok, jgStr(v));
		}
		if (!window.PublicKeyCredential) {
			done(0, "this browser has no WebAuthn");
			return;
		}
		o = JSON.parse(UTF8ToString(optsp));
		pk = o.publicKey;
		pk.challenge = jgB64.dec(pk.challenge);
		if (pk.user)
			pk.user.id = jgB64.dec(pk.user.id);
		(pk.excludeCredentials || []).forEach(function (c) {
			c.id = jgB64.dec(c.id);
		});
		(pk.allowCredentials || []).forEach(function (c) {
			c.id = jgB64.dec(c.id);
		});
		p = create ? navigator.credentials.create({ publicKey: pk }) :
		    navigator.credentials.get({ publicKey: pk });
		p.then(function (cred) {
			var r = cred.response, out = {
				id: cred.id,
				clientDataJSON: jgB64.enc(r.clientDataJSON)
			};

			if (create) {
				out.authenticatorData =
				    jgB64.enc(r.getAuthenticatorData());
				out.publicKey = jgB64.enc(r.getPublicKey());
				out.publicKeyAlgorithm =
				    r.getPublicKeyAlgorithm();
				out.transports = r.getTransports ?
				    r.getTransports() : [];
			} else {
				out.authenticatorData =
				    jgB64.enc(r.authenticatorData);
				out.signature = jgB64.enc(r.signature);
			}
			done(1, JSON.stringify(out));
		}).catch(function (err) {
			done(0, err && err.name === "NotAllowedError" ?
			    "cancelled or timed out" : String(err));
		});
	},

	jg_sw_register: function () {
		if ("serviceWorker" in navigator)
			navigator.serviceWorker.register("sw.js")
			    .catch(function (e) {
				console.warn("service worker:", e);
			});
	},

	jg_now: function () {
		return (Date.now());
	},

	jg_title__deps: ["$UTF8ToString"],
	jg_title: function (p) {
		document.title = UTF8ToString(p);
	},

	jg_hostname__deps: ["$jgStr"],
	jg_hostname: function () {
		return (jgStr(location.host));
	}
});
