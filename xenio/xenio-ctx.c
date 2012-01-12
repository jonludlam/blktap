/*
 * Copyright (c) 2010, Citrix Systems, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License,
 * version 2.1 only, as published by the Free Software Foundation,
 * with the special exception on linking described in file LICENSE.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <xenctrl.h>

#include "xenio.h"
#include "xenio-private.h"
#include "gntdev.h"

void
xenio_close(xenio_ctx_t *ctx)
{
	if (ctx->xce_handle >= 0) {
		xc_evtchn_close(ctx->xce_handle);
		ctx->xce_handle = NULL;
	}

	if (ctx->xcg_handle >= 0) {
		xc_gnttab_close(ctx->xcg_handle);
		ctx->xcg_handle = NULL;
	}

	free(ctx);
}

xenio_ctx_t*
xenio_open(void)
{
	xenio_ctx_t *ctx;
	int err;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		err = -errno;
		goto fail;
	}
	INIT_LIST_HEAD(&ctx->ifs);

	ctx->xce_handle = xc_evtchn_open(NULL, 0);
	if (ctx->xce_handle == NULL) {
		err = -errno;
		goto fail;
	}

	ctx->xcg_handle = xc_gnttab_open(NULL, 0);
	if (ctx->xcg_handle == NULL) {
		err = -errno;
		goto fail;
	}

	return ctx;

fail:
	if (ctx)
		xenio_close(ctx);
	errno = -err;

	return NULL;
}

int
xenio_event_fd(xenio_ctx_t *ctx)
{
	return xc_evtchn_fd(ctx->xce_handle);
}

