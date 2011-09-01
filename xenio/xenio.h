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

#ifndef _XENIO_H
#define _XENIO_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <xen/xen.h>
#include <xen/event_channel.h>
#include <xen/io/blkif.h>

typedef struct xenio_ctx xenio_ctx_t;
typedef struct xenio_blkif xenio_blkif_t;
typedef struct xenio_blkif_req xenio_blkif_req_t;

/*
 * xenio_open: Create a guest I/O context. Comprises event
 * notifications and granted memory mapping for one or a number of
 * data paths.
 *
 * Returns a handle to the context, NULL on failure. Sets errno.
 */
xenio_ctx_t *xenio_open(void);

void xenio_close(xenio_ctx_t *ctx);

/*
 * Frame pools.
 *
 * Pools back mmapped request grants with normal memory in the
 * caller's domain. Requisite for zero-copy I/O, such as using
 * O_DIRECT on blkif requests.
 *
 * Frame pools allocate local domain memory. They may have arbitrary
 * size, controllable in sysfs, but normally limited to match physical
 * layer capabilities. Multiple tasks/contexts may bind to the same
 * pool.
 */

/*
 * xenio_bind_frame_pool: Bind an I/O context to a frame pool
 * identified by @name. If the context does not exist, it is
 * created. Size and parameters are in sysfs. Names may be up to 36
 * bytes. All previous grant maps must be munmapped and revoked.
 *
 * Returns 0 on success, or -errno on error.
 *
 * ERRORS:
 *  EBUSY - Context had active grant and memory maps.
 *  EALREADY - Context already bound.
 */
int xenio_bind_frame_pool(xenio_ctx_t *ctx, const char *name);

/*
 * xenio_unbind_frame_pool: Unbind a bound frame pool from @ctx. All
 * previous grant maps must be munmapped and revoked. Last binding
 * dropped will garbage collect the pool.
 *
 * Returns 0 on success, or -errno on error.
 *
 * ERRORS:
 *  EBUSY -  Context had active grant and memory maps.
 *  ENOENT - Context not bound.
 */
int xenio_unbind_frame_pool(xenio_ctx_t *ctx);

/*
 * xenio_event_fd: Synchronous I/O multiplexing for guest
 * notifications.
 *
 * Returns a file descriptor suitable for polling.
 */
int xenio_event_fd(xenio_ctx_t *ctx);

/*
 * xenio_grant_event_fd: Synchronous I/O multiplexing for grant
 * mapping on congested frame pools.
 *
 * Returns a file descriptor suitable for polling.
 */
int xenio_grant_event_fd(xenio_ctx_t *ctx);

/*
 * Block I/O.
 */

enum {
	XENIO_BLKIF_PROTO_NATIVE = 1,
	XENIO_BLKIF_PROTO_X86_32 = 2,
	XENIO_BLKIF_PROTO_X86_64 = 3,
};

/*
 * xenio_blkif_connect: Connect to a Xen block I/O ring in @ctx.
 *
 * @domid: Remote domain id
 * @grefs: 1 or a number or sring grant references.
 * @order: Ring order -- number of grefs, log-2.
 * @port:  Remote interdomain event channel port.
 * @proto: Ring compat for 32/64-bit-guests.
 * @data:  User token for xenio_pending_blkif.
 *
 * Returns a connection handle, or NULL on failure. Sets errno.
 */
xenio_blkif_t *xenio_blkif_connect(xenio_ctx_t *ctx,
				   domid_t domid,
				   const grant_ref_t *grefs, int order,
				   evtchn_port_t port,
				   int proto,
				   void *data);

/*
 * xenio_blkif_disconnect: Disconnect and destroy a blkif handle.
 */
void xenio_blkif_disconnect(xenio_blkif_t *blkif);

/*
 * xenio_pending_blkif: Synchronous I/O multiplexing. Find all pending
 * blkifs on the given context, following guest event notification.
 */
xenio_blkif_t *xenio_pending_blkif(xenio_ctx_t *ctx, void **data);

/*
 * A single guest block request. Request structs are allocated by the
 * caller, but initialized by xenio.
 */

struct xenio_blkif_req {
	int                     op;
	uint64_t                id;
	int                     status;

	off64_t                 offset;
	struct xenio_blkif_seg {
		uint8_t         first;
		uint8_t         last;
	}                       segs[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	grant_ref_t             gref[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	int                     n_segs;

	unsigned int            pgoff;
	void                   *vma;
	struct iovec            iov[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	int                     n_iov;
};

/*
 * Returns the size of the shared I/O ring after connecting, in
 * numbers of requests.
 */
int xenio_blkif_ring_size(xenio_blkif_t *blkif);

/*
 * Read up to @count request messages from the shared I/O ring.
 * Caller indicates @final to reenable notifications before it stops
 * reading.
 */
int xenio_blkif_get_requests(xenio_blkif_t *blkif,
			     blkif_request_t **msgs, int count,
			     int final);

/*
 * Read a single request message.
 *
 * On success, returns 0 on leaves request content in
 * @req->{offset,segs,gref,n_segs}.
 *
 * Returns -errno of failure and sets req->status to BLKIF_RSP_ERROR.
 */
int xenio_blkif_parse_request(xenio_blkif_t *blkif,
			      blkif_request_t *msg, xenio_blkif_req_t *req);

/*
 * Trivial request mapping.
 *
 * Good for prototyping and applications not dealing with frame
 * pools. Or bound pools not prone to congestion.
 *
 * On success, returns 0 and leaves segment ranges in @req->vma and
 * @req->iovec. Sets and returns -errno on failure.
 */
int xenio_blkif_mmap_one(xenio_blkif_t *blkif, xenio_blkif_req_t *req);

int xenio_blkif_munmap_one(xenio_blkif_t *blkif, xenio_blkif_req_t *req);

/*
 * Batch request mapping.
 *
 * Good for applications with lots of guest I/O
 * on shared storage.
 */

/*
 * xenio_blkif_map_grants: Establish a grant mapping for a batch of
 * requests. If the blkif context was bound to a frame pool, mapped
 * requests will be backed with page structs. Despite this call
 * succeeding, the latter may happen only asynchronously.
 */
int64_t xenio_blkif_map_grants(xenio_blkif_t *blkif,
			       xenio_blkif_req_t **reqs, int count);

/*
 * xenio_blkif_unmap_grants: Revoke a grant mapping. Prevents
 * re-mmapping, but doesn't affect existing VMAs, so may forego
 * munmapping through xenio_blkif_munmap_request.
 */
int xenio_blkif_unmap_grants(xenio_blkif_t *blkif, int64_t id);

/*
 * xenio_blkif_mmap_requests: Map a batch of requests with established
 * grant mapping(s) into task memory.
 *
 * Iff the grant device was bound to a frame pool, this may fail
 * transiently with EAGAIN. Poll xenio_grant_event_fd for
 * notifications.
 *
 * On success, returns 0 and leaves segment ranges in @req->vma and
 * @req->iovec. Sets and returns -errno on failure.
 */
int xenio_blkif_mmap_requests(xenio_blkif_t *blkif,
			      xenio_blkif_req_t **reqs, int count);

/*
 * xenio_blkif_munmap_request: Unmap a previously mmapped @request.
 */
int xenio_blkif_munmap_request(xenio_blkif_t *blkif,
			       xenio_blkif_req_t *req);

/*
 * Write @count responses, with result codes according to
 */
void xenio_blkif_put_responses(xenio_blkif_t *blkif,
			       xenio_blkif_req_t **reqs, int count,
			       int final);

#endif /* _XENIO_H */
