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
