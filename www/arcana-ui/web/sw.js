/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The application shell works offline; the API never comes from a cache,
 * so jail data shown offline is always marked as the last known state.
 * The build replaces __BUILD__ with a checksum of the shell and __FILES__
 * with its file list, so a new build replaces the old cache.
 */
const CACHE = "arcana-__BUILD__";
const SHELL = __FILES__;

self.addEventListener("install", (e) => {
	/*
	 * From the server, not from the browser's own cache: the files
	 * come without a lifetime, so the browser keeps them as long as
	 * it sees fit, and a new shell made of old files is no update.
	 */
	e.waitUntil(caches.open(CACHE)
	    .then((c) => c.addAll(SHELL.map((u) =>
	    new Request(u, { cache: "reload" }))))
	    .then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
	e.waitUntil(caches.keys()
	    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE)
	    .map((k) => caches.delete(k))))
	    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
	const url = new URL(e.request.url);

	if (e.request.method !== "GET" || url.origin !== location.origin ||
	    url.pathname.startsWith("/api/"))
		return;
	/* Pages: the network first, the cached shell when offline. */
	if (e.request.mode === "navigate") {
		e.respondWith(fetch(e.request.url, { cache: "no-cache",
		    credentials: "same-origin" }).catch(() =>
		    caches.match("index.html")));
		return;
	}
	e.respondWith(caches.match(e.request, { ignoreSearch: true })
	    .then((hit) => hit || fetch(e.request)));
});

/* A notification of a finished task brings the console forward. */
self.addEventListener("notificationclick", (e) => {
	e.notification.close();
	e.waitUntil(self.clients.matchAll({ type: "window" }).then((cs) =>
	    cs.length > 0 ? cs[0].focus() : self.clients.openWindow("./")));
});
