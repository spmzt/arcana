/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * mkicon: draw the console's icon, a grid of jail cells with the middle
 * one lit, as a PNG of the given size.  "-m" draws the maskable variant:
 * the whole square filled, the grid inside the safe zone.  Run at build
 * time; writes with zlib(3) from base.
 *
 * usage: mkicon [-m] size out.png
 */

#include <sys/types.h>

#include <arpa/inet.h>

#include <err.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#define	SS	4		/* samples per pixel per axis */

static const double BG[3] = { 0x04, 0x07, 0x0c };
static const double CYAN[3] = { 0x3b, 0xe8, 0xff };

static void	chunk(FILE *, const char *, const unsigned char *, size_t);
static bool	in_round(double, double, double, double);
static double	coverage(double, double, bool, double *);

static void
chunk(FILE *fp, const char *tag, const unsigned char *data, size_t len)
{
	uint32_t	n, crc;

	n = htonl((uint32_t)len);
	fwrite(&n, 4, 1, fp);
	fwrite(tag, 1, 4, fp);
	if (len > 0)
		fwrite(data, 1, len, fp);
	crc = (uint32_t)crc32(0, (const unsigned char *)tag, 4);
	crc = (uint32_t)crc32(crc, data, (uInt)len);
	crc = htonl(crc);
	fwrite(&crc, 4, 1, fp);
}

/* Inside a square of side 1 with corner radius r, at (x, y) in [0,1]. */
static bool
in_round(double x, double y, double r, double inset)
{
	double	cx, cy;

	if (x < inset || y < inset || x > 1 - inset || y > 1 - inset)
		return (false);
	cx = fmin(fmax(x, inset + r), 1 - inset - r);
	cy = fmin(fmax(y, inset + r), 1 - inset - r);
	return ((x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r);
}

/*
 * What the point (x, y) shows: returns how much of it is cyan; *alpha is
 * whether it is inside the icon at all.
 */
static double
coverage(double x, double y, bool maskable, double *alpha)
{
	double	g0, g1, cell, lw, u, v, d;
	int	i;

	*alpha = maskable || in_round(x, y, 0.22, 0) ? 1 : 0;
	if (*alpha == 0)
		return (0);
	/* The grid: 40/64 of the icon, or the 80% safe zone for maskable. */
	g0 = maskable ? 0.28 : 12.0 / 64;
	g1 = 1 - g0;
	cell = (g1 - g0) / 3;
	lw = (maskable ? 1.9 : 2.4) / 64;
	if (x >= g0 + cell && x <= g0 + 2 * cell && y >= g0 + cell &&
	    y <= g0 + 2 * cell)
		return (0.95);
	for (i = 0; i <= 3; i++) {
		u = g0 + i * cell;
		if (fabs(x - u) <= lw / 2 && y >= g0 - lw / 2 &&
		    y <= g1 + lw / 2)
			return (0.5);
		if (fabs(y - u) <= lw / 2 && x >= g0 - lw / 2 &&
		    x <= g1 + lw / 2)
			return (0.5);
	}
	/* A soft glow around the lit cell. */
	u = fmax(fmax(g0 + cell - x, x - (g0 + 2 * cell)), 0);
	v = fmax(fmax(g0 + cell - y, y - (g0 + 2 * cell)), 0);
	d = sqrt(u * u + v * v);
	return (0.35 * exp(-d * 28));
}

int
main(int argc, char *argv[])
{
	unsigned char	*raw, *z, hdr[13];
	double		 a, c, sa, sc, x, y;
	uLongf		 zlen;
	size_t		 rowlen;
	FILE		*fp;
	bool		 maskable;
	int		 ch, size, px, py, sx, sy, k;

	maskable = false;
	while ((ch = getopt(argc, argv, "m")) != -1) {
		if (ch != 'm') {
			fprintf(stderr, "usage: mkicon [-m] size out.png\n");
			return (2);
		}
		maskable = true;
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 || (size = atoi(argv[0])) < 16 || size > 4096) {
		fprintf(stderr, "usage: mkicon [-m] size out.png\n");
		return (2);
	}
	rowlen = (size_t)size * 4 + 1;
	if ((raw = calloc((size_t)size, rowlen)) == NULL)
		err(1, "calloc");
	for (py = 0; py < size; py++) {
		raw[py * rowlen] = 0;		/* filter: none */
		for (px = 0; px < size; px++) {
			sa = sc = 0;
			for (sy = 0; sy < SS; sy++) {
				for (sx = 0; sx < SS; sx++) {
					x = (px + (sx + 0.5) / SS) / size;
					y = (py + (sy + 0.5) / SS) / size;
					c = coverage(x, y, maskable, &a);
					sa += a;
					sc += c * a;
				}
			}
			a = sa / (SS * SS);
			c = sa > 0 ? sc / sa : 0;
			for (k = 0; k < 3; k++)
				raw[py * rowlen + 1 + px * 4 + k] =
				    (unsigned char)lround(BG[k] +
				    (CYAN[k] - BG[k]) * c);
			raw[py * rowlen + 1 + px * 4 + 3] =
			    (unsigned char)lround(255 * a);
		}
	}
	zlen = compressBound((uLong)(rowlen * size));
	if ((z = malloc(zlen)) == NULL)
		err(1, "malloc");
	if (compress2(z, &zlen, raw, (uLong)(rowlen * size), 9) != Z_OK)
		errx(1, "compress2 failed");

	if ((fp = fopen(argv[1], "wb")) == NULL)
		err(1, "%s", argv[1]);
	fwrite("\x89PNG\r\n\x1a\n", 1, 8, fp);
	*(uint32_t *)(void *)hdr = htonl((uint32_t)size);
	*(uint32_t *)(void *)(hdr + 4) = htonl((uint32_t)size);
	hdr[8] = 8;		/* bit depth */
	hdr[9] = 6;		/* RGBA */
	hdr[10] = hdr[11] = hdr[12] = 0;
	chunk(fp, "IHDR", hdr, sizeof(hdr));
	chunk(fp, "IDAT", z, zlen);
	chunk(fp, "IEND", NULL, 0);
	if (fclose(fp) != 0)
		err(1, "%s", argv[1]);
	free(raw);
	free(z);
	return (0);
}
