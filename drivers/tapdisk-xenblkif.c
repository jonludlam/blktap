/*
 * Copyright (c) 2010, Citrix Systems, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <xenctrl.h>
#include <xen/xen.h>
#include <xen/io/blkif.h>
#include <sys/mman.h>

#include "tapdisk.h"
#include "tapdisk-xenblkif.h"
#include "tapdisk-server.h"
#include "tapdisk-log.h"
#include "xenio.h"
#include "list.h"

#define unlikely(_cond)         (_cond)
#define BUG_ON(_cond)           if (unlikely(_cond)) { td_panic(); }

#define WARN(_fmt, _args ...)						\
	tlog_syslog(LOG_WARNING,					\
		    "WARNING: "_fmt" in %s:%d",			\
		    ##_args,  __func__, __LINE__)			\

#define WARN_ON(_cond) if (unlikely(_cond)) WARN(#_cond)

#define WARN_ON_WITH(_cond, _conv, _expr)				\
	if (unlikely(_cond)) WARN("%s, %s = %"_conv,			\
				  #_cond, #_expr, _expr)

#define WARN_ON_WITH_ERRNO(_cond)					\
	if (unlikely(_cond)) WARN("errno = %d (%s)",			\
				  errno, strerror(errno))

#define unexpected(_cond)						\
({	int __cond = (_cond);						\
	if (unlikely(__cond)) {					\
		tlog_syslog("WARNING: %s = %d in %s:%d",		\
			    #_cond, _cond,  __func__, __LINE__);	\
	}								\
	__cond;							\
})

#define containerof(_ptr, _type, _member)			\
	((_type*)((void*)(_ptr) - offsetof(_type, _member)))

typedef struct td_xenio_ctx td_xenio_ctx_t;
typedef struct td_xenblkif td_xenblkif_t;
typedef struct td_xenblkif_req td_xenblkif_req_t;

struct td_xenio_ctx {
	char                   *pool;

	xenio_ctx_t            *xenio;

	event_id_t              ring_event;
	event_id_t              grant_event;

	struct list_head        blkifs;
	struct list_head        entry;
};

static LIST_HEAD(_td_xenio_ctxs);

#define tapdisk_xenio_for_each_ctx(_ctx) \
	list_for_each_entry(_ctx, &_td_xenio_ctxs, entry)

#define tapdisk_xenio_find_ctx(_ctx, _cond)				\
	do {								\
		tapdisk_xenio_for_each_ctx(_ctx) {			\
			if (_cond)					\
				break;					\
		}							\
		if (_ctx == list_entry(&_td_xenio_ctxs,		\
				       td_xenio_ctx_t, entry))		\
			_ctx = NULL;					\
	} while (0)

#define tapdisk_xenio_for_each_blkif(_blkif, _ctx)			\
	list_for_each_entry(_blkif, &(_ctx)->blkifs, ctx_entry)

#define tapdisk_xenio_ctx_find_blkif(_ctx, _blkif, _cond)		\
	do {								\
		tapdisk_xenio_for_each_blkif(_blkif, _ctx) {		\
			if (_cond)					\
				break;					\
		}							\
		if (_blkif == list_entry(&(_ctx)->blkifs,		\
					 td_xenblkif_t, ctx_entry))	\
			_blkif = NULL;					\
	} while (0)

struct td_xenblkif_stats {
	struct {
		unsigned long long      in;
		unsigned long long      out;
	} reqs;
	struct {
		unsigned long long      in;
		unsigned long long      out;
	} kicks;
	struct {
		unsigned long long      msg;
		unsigned long long      map;
		unsigned long long      vbd;
		unsigned long long      img;
	} errors;
};

struct td_xenblkif {
	int                       domid;
	int                       devid;
	int                       rport;

	td_xenio_ctx_t           *ctx;
	struct list_head          ctx_entry;

	xenio_blkif_t            *xenio;
	int                       port;
	int                       ring_size;

	td_xenblkif_req_t        *reqs;
	int                       n_reqs_free;
	blkif_request_t         **reqs_free;

	td_vbd_t                 *vbd;

	struct td_xenblkif_stats  stats;
};

struct td_xenblkif_req {
	td_vbd_request_t          vreq;
	xenio_blkif_req_t         xenio;
	char                      name[16+1];
	struct td_iovec           iov[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	blkif_request_t           msg;
};

#define DBG(_fmt, _args ...)    tlog_syslog(LOG_DEBUG, _fmt, ##_args)

#define msg_to_tapreq(_req)				\
	containerof(_req, td_xenblkif_req_t, msg)

static void
tapdisk_xenblkif_free_request(td_xenblkif_t *blkif,
			      td_xenblkif_req_t *tapreq)
{
	blkif->n_reqs_free++;
	BUG_ON(blkif->n_reqs_free > blkif->ring_size);
	blkif->reqs_free[blkif->ring_size -
			 blkif->n_reqs_free] = &tapreq->msg;
}

static void
tapdisk_xenblkif_reqs_free(td_xenblkif_t *blkif)
{
	if (blkif->reqs) {
		free(blkif->reqs);
		blkif->reqs = NULL;
	}

	if (blkif->reqs_free) {
		free(blkif->reqs_free);
		blkif->reqs_free = NULL;
	}
}

static int
tapdisk_xenblkif_reqs_init(td_xenblkif_t *blkif)
{
	int i, err;

	blkif->ring_size = xenio_blkif_ring_size(blkif->xenio);

	blkif->reqs = malloc(blkif->ring_size
			     * sizeof(td_xenblkif_req_t));
	if (!blkif->reqs) {
		err = -errno;
		goto fail;
	}

	blkif->reqs_free = malloc(blkif->ring_size *
				  sizeof(xenio_blkif_req_t*));
	if (!blkif->reqs_free) {
		err = -errno;
		goto fail;
	}

	blkif->n_reqs_free = 0;
	for (i = 0; i < blkif->ring_size; i++)
		tapdisk_xenblkif_free_request(blkif, &blkif->reqs[i]);

	return 0;

fail:
	tapdisk_xenblkif_reqs_free(blkif);
	return err;
}

static void
tapdisk_xenblkif_complete_request(td_xenblkif_t *blkif,
				  td_xenblkif_req_t *tapreq, int error,
				  int final)
{
	xenio_blkif_req_t *req = &tapreq->xenio;
	int err;

	if (req->vma) {
		err = xenio_blkif_munmap_one(blkif->xenio, req);
		WARN_ON_WITH_ERRNO(err);
	}

	req->status = error ? BLKIF_RSP_ERROR : BLKIF_RSP_OKAY;
	xenio_blkif_put_responses(blkif->xenio, &req, 1, final);

	tapdisk_xenblkif_free_request(blkif, tapreq);

	blkif->stats.reqs.out++;
	if (final)
		blkif->stats.kicks.out++;
}

static void
__tapdisk_xenblkif_request_cb(td_vbd_request_t *vreq, int error,
			      void *token, int final)
{
	td_xenblkif_req_t *tapreq = containerof(vreq, td_xenblkif_req_t, vreq);
	td_xenblkif_t *blkif = token;

	tapdisk_xenblkif_complete_request(blkif, tapreq, error, final);
	if (error)
		blkif->stats.errors.img++;
}

static void
tapdisk_xenblkif_vector_request(td_xenblkif_t *blkif,
				td_xenblkif_req_t *tapreq)
{
	xenio_blkif_req_t *req = &tapreq->xenio;
	td_vbd_request_t *vreq = &tapreq->vreq;
	int i;

	for (i = 0; i < req->n_iov; i++) {
		struct iovec    *iov  = req->iov;
		struct td_iovec *tiov = tapreq->iov;

		tiov->base = iov->iov_base;
		tiov->secs = iov->iov_len >> SECTOR_SHIFT;
	}

	vreq->iov    = tapreq->iov;
	vreq->iovcnt = req->n_iov;
	vreq->sec    = tapreq->xenio.offset >> SECTOR_SHIFT;
}

static int
tapdisk_xenblkif_make_vbd_request(td_xenblkif_t *blkif,
				  td_xenblkif_req_t *tapreq)
{
	xenio_blkif_req_t *req = &tapreq->xenio;
	td_vbd_request_t *vreq = &tapreq->vreq;
	int op, err;

	switch (req->op) {
	case BLKIF_OP_READ:
		op = TD_OP_READ;
		break;
	case BLKIF_OP_WRITE:
		op = TD_OP_WRITE;
		break;
	default:
		err = -EOPNOTSUPP;
		return err;
	}

	err = xenio_blkif_mmap_one(blkif->xenio, req);
	WARN_ON_WITH_ERRNO(err);
	if (err)
		return err;

	snprintf(tapreq->name, sizeof(tapreq->name),
		 "xenvbd-%d-%d.%llx",
		 blkif->domid, blkif->devid, tapreq->xenio.id);

	vreq->op    = op;
	vreq->name  = tapreq->name;
	vreq->token = blkif;
	vreq->cb    = __tapdisk_xenblkif_request_cb;

	tapdisk_xenblkif_vector_request(blkif, tapreq);

	return 0;
}

void
tapdisk_xenblkif_queue_requests(td_xenblkif_t *blkif,
				blkif_request_t **reqs, int n_reqs)
{
	int i, err, errors = 0;

	for (i = 0; i < n_reqs; i++) {
		blkif_request_t *msg = reqs[i];
		td_xenblkif_req_t *tapreq = msg_to_tapreq(msg);

		errors++;

		err = xenio_blkif_parse_request(blkif->xenio,
						msg, &tapreq->xenio);
		if (err) {
			blkif->stats.errors.msg++;
			goto fail_req;
		}

		err = tapdisk_xenblkif_make_vbd_request(blkif, tapreq);
		if (err) {
			blkif->stats.errors.map++;
			goto fail_req;
		}

		err = tapdisk_vbd_queue_request(blkif->vbd, &tapreq->vreq);
		if (err) {
			blkif->stats.errors.vbd++;
			goto fail_req;
		}

		errors--;
		continue;

	fail_req:
		tapdisk_xenblkif_complete_request(blkif, tapreq, err, 1);
	}

	if (errors)
		xenio_blkif_put_responses(blkif->xenio, NULL, 0, 1);
}

void
tapdisk_xenblkif_ring_event(td_xenblkif_t *blkif)
{
	int n_reqs, final, err;

	blkif->stats.kicks.in++;

	final = 0;
	do {
		blkif_request_t **reqs = &blkif->reqs_free[blkif->ring_size -
							   blkif->n_reqs_free];

		n_reqs = xenio_blkif_get_requests(blkif->xenio,
						  reqs, blkif->n_reqs_free,
						  final);
		BUG_ON(n_reqs < 0);
		if (!n_reqs)
			break;

		blkif->n_reqs_free   -= n_reqs;
		blkif->stats.reqs.in += n_reqs;

		tapdisk_xenblkif_queue_requests(blkif, reqs, n_reqs);

		final = 1;
	} while (1);
}

void
tapdisk_xenblkif_grant_event(td_xenblkif_t *blkif)
{
	DBG("tapdisk_xenblkif_grant_event: rd=%d devid=%d",
	    blkif->domid, blkif->devid);
}

static void
tapdisk_xenio_ctx_ring_event(event_id_t id, char mode, void *private)
{
	td_xenio_ctx_t *ctx = private;
	xenio_blkif_t *xenio;
	td_xenblkif_t *blkif;
	void *data;

	xenio = xenio_pending_blkif(ctx->xenio,
				    (void**)&blkif);
	if (xenio)
		tapdisk_xenblkif_ring_event(blkif);
}

static void
tapdisk_xenio_ctx_grant_event(event_id_t id, char mode, void *private)
{
	td_xenio_ctx_t *ctx = private;
	td_xenblkif_t *blkif;

	tapdisk_xenio_for_each_blkif(blkif, ctx)
		tapdisk_xenblkif_grant_event(blkif);
}

static void
tapdisk_xenio_ctx_close(td_xenio_ctx_t *ctx)
{
	if (ctx->ring_event >= 0) {
		tapdisk_server_unregister_event(ctx->ring_event);
		ctx->ring_event = -1;
	}

	if (ctx->grant_event >= 0) {
		tapdisk_server_unregister_event(ctx->grant_event);
		ctx->grant_event = -1;
	}

	if (ctx->xenio) {
		xenio_close(ctx->xenio);
		ctx->xenio = NULL;
	}

	list_del(&ctx->entry);
}

static int
tapdisk_xenio_ctx_open(const char *pool)
{
	td_xenio_ctx_t *ctx;
	int fd, err;

	if (pool && !strlen(pool))
		return -EINVAL;

	ctx = calloc(1, sizeof(*ctx));

	ctx->xenio       = NULL;
	ctx->ring_event  = -1;
	ctx->grant_event = -1;
	INIT_LIST_HEAD(&ctx->blkifs);
	list_add(&ctx->entry, &_td_xenio_ctxs);

	ctx->xenio = xenio_open();
	WARN_ON_WITH_ERRNO(!ctx->xenio);
	if (!ctx->xenio) {
		err = -errno;
		goto fail;
	}

	/*
	 * poll ring events.
	 */

	fd = xenio_event_fd(ctx->xenio);
	if (fd < 0) {
		err = -errno;
		goto fail;
	}

	ctx->ring_event =
		tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					      fd, 0,
					      tapdisk_xenio_ctx_ring_event,
					      ctx);
	if (ctx->ring_event < 0) {
		err = ctx->ring_event;
		goto fail;
	}

	/*
	 * poll gntdev mmap events
	 */

	fd = xenio_grant_event_fd(ctx->xenio);
	if (fd < 0) {
		err = -errno;
		goto fail;
	}

	ctx->grant_event =
		tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					      fd, 0,
					      tapdisk_xenio_ctx_grant_event,
					      ctx);
	if (ctx->grant_event < 0) {
		err = ctx->grant_event;
		goto fail;
	}

	if (pool) {
		ctx->pool = strdup(pool);
		if (!ctx->pool) {
			err = -errno;
			goto fail;
		}
	} else
		ctx->pool = TD_XENBLKIF_DEFAULT_POOL;

	if (ctx->pool) {
		err = xenio_bind_frame_pool(ctx->xenio, ctx->pool);
		if (err) {
			err = -errno;
			goto fail;
		}
	}

	return 0;

fail:
	tapdisk_xenio_ctx_close(ctx);
	return err;
}

static int
__td_xenio_ctx_match(td_xenio_ctx_t *ctx, const char *pool)
{
	if (unlikely(!pool)) {
		if (TD_XENBLKIF_DEFAULT_POOL)
			return !strcmp(ctx->pool, TD_XENBLKIF_DEFAULT_POOL);
		else
			return !ctx->pool;
	}

	return !strcmp(ctx->pool, pool);
}

static int
tapdisk_xenio_ctx_get(const char *pool, td_xenio_ctx_t **_ctx)
{
	td_xenio_ctx_t *ctx;
	int err = 0;

retry:
	tapdisk_xenio_find_ctx(ctx,
			       __td_xenio_ctx_match(ctx, pool));
	if (!ctx) {
		err = tapdisk_xenio_ctx_open(pool);
		if (!err)
			goto retry;
	}

	*_ctx = ctx;

	return err;
}

static void
tapdisk_xenio_ctx_put(td_xenio_ctx_t *ctx)
{
	if (list_empty(&ctx->blkifs))
		tapdisk_xenio_ctx_close(ctx);
}

static td_xenblkif_t*
tapdisk_xenblkif_find(domid_t domid, int devid)
{
	td_xenblkif_t *blkif = NULL;
	td_xenio_ctx_t *ctx;

	tapdisk_xenio_for_each_ctx(ctx) {
		tapdisk_xenio_ctx_find_blkif(ctx, blkif,
					     blkif->domid == domid &&
					     blkif->devid == devid);
		if (blkif)
			return blkif;
	}

	return NULL;
}

static void
tapdisk_xenblkif_destroy(td_xenblkif_t *blkif)
{
	tapdisk_xenblkif_reqs_free(blkif);

	if (blkif->xenio) {
		xenio_blkif_disconnect(blkif->xenio);
		blkif->xenio = NULL;
	}

	if (blkif->ctx) {
		list_del(&blkif->ctx_entry);
		tapdisk_xenio_ctx_put(blkif->ctx);
		blkif->ctx = NULL;
	}
}

int
tapdisk_xenblkif_disconnect(domid_t domid, int devid)
{
	td_xenblkif_t *blkif;

	blkif = tapdisk_xenblkif_find(domid, devid);
	if (!blkif)
		return -ESRCH;

	if (blkif->n_reqs_free != blkif->ring_size)
		return -EBUSY;

	tapdisk_xenblkif_destroy(blkif);

	return 0;
}

int
tapdisk_xenblkif_connect(domid_t domid, int devid,
			 const grant_ref_t *grefs, int order, int proto,
			 evtchn_port_t port, const char *pool, td_vbd_t *vbd)
{
	td_xenblkif_t *blkif = NULL;
	td_xenio_ctx_t *ctx;
	int err;

	blkif = tapdisk_xenblkif_find(domid, devid);
	if (blkif)
		return -EEXIST;

	blkif = calloc(1, sizeof(*blkif));
	if (!blkif) {
		err = -errno;
		goto fail;
	}

	err = tapdisk_xenio_ctx_get(pool, &ctx);
	if (err)
		goto fail;

	blkif->domid = domid;
	blkif->devid = devid;
	blkif->rport = port;
	blkif->vbd   = vbd;
	blkif->ctx   = ctx;
	list_add_tail(&blkif->ctx_entry, &ctx->blkifs);

	blkif->xenio = xenio_blkif_connect(ctx->xenio,
					   domid, grefs, order, port,
					   proto,
					   blkif);
	if (!blkif->xenio) {
		err = -errno;
		goto fail;
	}

	err = tapdisk_xenblkif_reqs_init(blkif);
	if (err)
		goto fail;

	return 0;

fail:
	if (blkif)
		tapdisk_xenblkif_destroy(blkif);

	return err;
}

static void
__tapdisk_xenblkif_stats(td_xenblkif_t *blkif, td_stats_t *st)
{
	tapdisk_stats_field(st, "pool", blkif->ctx->pool);
	tapdisk_stats_field(st, "domid", "d", blkif->domid);
	tapdisk_stats_field(st, "devid", "d", blkif->devid);

	tapdisk_stats_field(st, "reqs", "[");
	tapdisk_stats_val(st, "llu", blkif->stats.reqs.in);
	tapdisk_stats_val(st, "llu", blkif->stats.reqs.out);
	tapdisk_stats_leave(st, ']');

	tapdisk_stats_field(st, "kicks", "[");
	tapdisk_stats_val(st, "llu", blkif->stats.kicks.in);
	tapdisk_stats_val(st, "llu", blkif->stats.kicks.out);
	tapdisk_stats_leave(st, ']');

	tapdisk_stats_field(st, "errors", "{");
	tapdisk_stats_field(st, "msg", "llu", blkif->stats.errors.msg);
	tapdisk_stats_field(st, "map", "llu", blkif->stats.errors.map);
	tapdisk_stats_field(st, "vbq", "llu", blkif->stats.errors.vbd);
	tapdisk_stats_field(st, "img", "llu", blkif->stats.errors.img);
	tapdisk_stats_leave(st, ']');
}

void
tapdisk_xenblkif_stats(td_vbd_t *vbd, td_stats_t *st)
{
	td_xenblkif_t *blkif;
	td_xenio_ctx_t *ctx;
	int matches;

	tapdisk_xenio_for_each_ctx(ctx) {
		tapdisk_xenio_for_each_blkif(blkif, ctx) {
			if (blkif->vbd == vbd) {
				matches = 1;
				break;
			}
		}
	}
	if (!matches)
		return;

	tapdisk_stats_field(st, "xen-blkifs", "[");

	tapdisk_xenio_for_each_ctx(ctx) {
		tapdisk_xenio_for_each_blkif(blkif, ctx) {
			if (blkif->vbd != vbd)
				continue;

			tapdisk_stats_enter(st, '{');
			__tapdisk_xenblkif_stats(blkif, st);
			tapdisk_stats_leave(st, '}');
		}
	}

	tapdisk_stats_leave(st, ']');
}
