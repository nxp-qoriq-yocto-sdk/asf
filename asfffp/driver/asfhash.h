/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/* The BJ3 Hash function (bj3mix)
 * is drived from (http://burtleburtle.net/bob/):
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 * Which is under the license "You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty."
*/
#ifndef __ASFHASHAPI_H
#define __ASFHASHAPI_H


/* BJ3 Hash */
#define rot(x, k) (((x)<<(k)) | ((x)>>(32-(k))))
#define ASF_BJ3_MIX(a, b, c) \
{ \
	a -= c; a ^= rot(c, 4); c += b; \
	b -= a; b ^= rot(a, 6); a += c; \
	c -= b; c ^= rot(b, 8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b, 4); b += a; \
}

#endif

