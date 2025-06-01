/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/types.h>

/* --------------------------------------------------------------------
 * First pull in libbpf’s helper header so we inherit its canonical
 * map-descriptor macros.  We then guard our own fall-back definitions
 * with #ifndef to avoid the “macro redefined” errors that clang/LLVM
 * promotes to -Werror.
 * ------------------------------------------------------------------ */
#include <bpf/libbpf/bpf_helpers.h>

#ifndef __uint
# define __uint(name, val)  int (*name)[val]
#endif

#ifndef __type
# define __type(name, val)  typeof(val) *name
#endif

#ifndef __array
# define __array(name, val) typeof(val) *name[]
#endif

#define LIBBPF_PIN_BY_NAME 1

/* Never reuse a pinned map during ELF loading. Always create and populate
 * from scratch, then overwrite the pin after all entry-point programs
 * are successfully attached. Used for tail-call maps that should never
 * be repopulated while a program is still actively using them.
 */
#define CILIUM_PIN_REPLACE (1 << 4)

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};
