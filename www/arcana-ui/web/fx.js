/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Visual effects are on unless this browser turned them off.  Loaded in
 * the head so the class is there before the first paint; a file of its
 * own because the page's Content-Security-Policy allows no inline script.
 */
try {
	if (localStorage.getItem("arc_fx") !== "0")
		document.documentElement.classList.add("fx");
} catch (e) {
	document.documentElement.classList.add("fx");
}

/* The theme chosen in this browser; none is the default one. */
try {
	var arcTheme = localStorage.getItem("arc_theme");

	/*
	 * On a phone, where nothing was chosen, the plain one: glow and
	 * a display face are much on a small screen.  Tron chosen there
	 * is kept as "tron", which the stylesheet has no rules for.
	 */
	if (arcTheme)
		document.documentElement.dataset.theme = arcTheme;
	else if (window.matchMedia("(max-width: 620px)").matches)
		document.documentElement.dataset.theme = "slate";
} catch (e) {
}
