// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include "lib/common.h"

/* Include custom header file (.h) containing the implementation for
 * custom_prog(), for example:
 *
 *     #include "bytecount.h"
 */
#include "bytecount.h"

__section("custom")
int custom_hook(struct __ctx_buff *ctx)
{
	int ret = ctx_load_meta(ctx, CB_CUSTOM_CALLS);
	int identity = get_identity(ctx);

	/* Call user-defined function from custom header file. */
	custom_prog(ctx, identity);

	/* Return action code selected from parent program, independently of
	 * what the custom function does, to maintain datapath consistency.
	 */
	return ret;
}
