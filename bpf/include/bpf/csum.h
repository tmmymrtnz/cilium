/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "compiler.h"
#include "helpers.h"

static __always_inline __sum16 csum_fold(__wsum csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__sum16)~csum;
}

static __always_inline __wsum csum_unfold(__sum16 csum)
{
	return (__wsum)csum;
}

static __always_inline __wsum csum_add(__wsum csum, __wsum addend)
{
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

/* Kernel helper wrapper for arbitrary-sized buffers. */
static __always_inline __wsum csum_diff(const void *from, __u32 size_from,
					const void *to,   __u32 size_to,
					__u32 seed)
{
	if (__builtin_constant_p(size_from) &&
	    __builtin_constant_p(size_to)) {
		/* Fast-path for the common 4-byte case. */
		if (size_from == 4 && size_to == 4 &&
		    __builtin_constant_p(seed) && seed == 0)
			return csum_add(~(*(__u32 *)from), *(__u32 *)to);
		if (size_from == 4 && size_to == 4)
			return csum_add(seed,
					csum_add(~(*(__u32 *)from),
						 *(__u32 *)to));
	}

	return csum_diff_external(from, size_from, to, size_to, seed);
}

/* ------------------------------------------------------------------ */
/* Convenience wrapper for the very common IPv4-field update case.    */
/* Computes the diff between two 32-bit addresses, keeping the seed   */
/* semantics identical to csum_diff().                                */
/* ------------------------------------------------------------------ */
static __always_inline __wsum
csum_diff4(__be32 from, __be32 to, __wsum seed)
{
	/* sizeof(from) == sizeof(to) == 4 */
	return csum_diff(&from, sizeof(from), &to, sizeof(to), seed);
}
