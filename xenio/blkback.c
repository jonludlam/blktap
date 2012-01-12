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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <xs.h>
#include <xen/xen.h>
#include <xen/io/xenbus.h>
#include <syslog.h>

#include "list.h"
#include "xenio.h"

#define likely(_cond)           __builtin_expect(!!(_cond), 1)
#define unlikely(_cond)         __builtin_expect(!!(_cond), 0)
#define __printf(_f, _a)        __attribute__((format (printf, _f, _a)))
#define __scanf(_f, _a)         __attribute__((format (scanf, _f, _a)))

#define BUG()                   abort()
#define BUG_ON(_cond)           if (unlikely(_cond)) BUG()

void (*xenio_vlog)(int prio, const char *fmt, va_list ap) = vsyslog;

__printf(2, 3)
static inline void
xenio_log(int prio, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	xenio_vlog(prio, fmt, ap);
	va_end(ap);
}

#define DBG(_fmt, _args...)  xenio_log(LOG_DEBUG, _fmt, ##_args)
#define INFO(_fmt, _args...) xenio_log(LOG_INFO, _fmt, ##_args)
#define WARN(_fmt, _args...) xenio_log(LOG_WARNING, _fmt, ##_args)

typedef struct xenio_backend xenio_backend_t;
typedef struct xenio_device xenio_device_t;

struct xenio_backend_ops {
	int  (*probe)(xenio_device_t *, domid_t, const char *);
	void (*remove)(xenio_device_t *);
	void (*frontend_changed)(xenio_device_t *, XenbusState);
};

struct xenio_device {
	char                           *name;
	xenio_backend_t                *backend;
	struct list_head                backend_entry;
	long long                       serial;

	domid_t                         domid;
	char                           *frontend_path;
	char                           *frontend_state_path;

	void                           *private;
};

struct xenio_backend {
	struct xs_handle               *xs;
	xs_transaction_t                xst;

	char                           *name;
	char                           *path;
	char                           *token;

	struct list_head                devices;

	long long                       serial;

	const struct xenio_backend_ops *ops;
};

#define xenio_backend_for_each_device(_device, _next, _backend)	\
	list_for_each_entry_safe(_device, _next,			\
				 &(_backend)->devices, backend_entry)

static char*
vmprintf(const char *fmt, va_list ap)
{
	char *s;
	int n;

	n = vasprintf(&s, fmt, ap);
	if (n < 0)
		s = NULL;

	return s;
}

__printf(1, 2)
static char*
mprintf(const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	s = vmprintf(fmt, ap);
	va_end(ap);

	return s;
}

static char *
xenio_xs_vread(struct xs_handle *xs, xs_transaction_t xst,
	       const char *fmt, va_list ap)
{
	char *path, *data, *s = NULL;
	unsigned int len;

	path = vmprintf(fmt, ap);
	data = xs_read(xs, xst, path, &len);
	free(path);

	if (data) {
		s = strndup(data, len);
		free(data);
	}

	return s;
}

__printf(3, 4)
static char *
xenio_xs_read(struct xs_handle *xs, xs_transaction_t xst,
	      const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	s = xenio_xs_vread(xs, xst, fmt, ap);
	va_end(ap);

	return s;
}

__printf(3, 4)
static bool
xenio_xs_exists(struct xs_handle *xs, xs_transaction_t xst,
		const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	s = xenio_xs_vread(xs, xst, fmt, ap);
	va_end(ap);
	if (s)
		free(s);

	return s != NULL;
}

static char *
xenio_device_read(xenio_device_t *device, const char *path)
{
	xenio_backend_t *backend = device->backend;

	return xenio_xs_read(backend->xs, backend->xst,
			     "%s/%d/%s/%s",
			     backend->path, device->domid, device->name, path);
}

static int
xenio_device_vscanf(xenio_device_t *device,
		    const char *path, const char *fmt, va_list ap)
{
	char *s;
	int n;

	s = xenio_device_read(device, path);
	if (!s)
		return -1;

	DBG("%s <- %s\n", path, s);
	n = vsscanf(s, fmt, ap);
	free(s);

	return n;
}

__scanf(3, 4)
static int
xenio_device_scanf(xenio_device_t *device,
		   const char *path, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = xenio_device_vscanf(device, path, fmt, ap);
	va_end(ap);

	return n;
}

static char *
xenio_device_read_otherend(xenio_device_t *device, const char *path)
{
	xenio_backend_t *backend = device->backend;

	return xenio_xs_read(backend->xs, backend->xst,
			     "%s/%s",
			     device->frontend_path, path);
}

static int
xenio_device_vscanf_otherend(xenio_device_t *device,
			     const char *path, const char *fmt, va_list ap)
{
	char *s;
	int n;

	s = xenio_device_read_otherend(device, path);
	if (!s)
		return -1;

	n = vsscanf(s, fmt, ap);
	free(s);

	return n;
}

__scanf(3, 4)
static int
xenio_device_scanf_otherend(xenio_device_t *device,
			    const char *path, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = xenio_device_vscanf_otherend(device, path, fmt, ap);
	va_end(ap);

	return n;
}

static int
xenio_device_vprintf(xenio_device_t *device,
		     const char *key, int mkread, const char *fmt, va_list ap)
{
	xenio_backend_t *backend = device->backend;
	char *path = NULL, *val = NULL;
	bool nerr;
	int err;

	path = mprintf("%s/%d/%s/%s",
		       backend->path, device->domid, device->name, key);
	if (!path) {
		err = -errno;
		goto fail;
	}

	val = vmprintf(fmt, ap);
	if (!val) {
		err = -errno;
		goto fail;
	}

	DBG("%s -> %s\n", path, val);
	nerr = xs_write(backend->xs, backend->xst,
			path, val, strlen(val));
	if (!nerr) {
		err = -errno;
		goto fail;
	}

	if (mkread) {
		struct xs_permissions perms = {
			device->domid,
			XS_PERM_READ
		};

		nerr = xs_set_permissions(backend->xs, backend->xst,
					  path, &perms, 1);
		if (!nerr) {
			err = -errno;
			goto fail;
		}
	}

	err = 0;

fail:
	if (path)
		free(path);
	if (val)
		free(val);

	return err;
}

__printf(4, 5)
static int
xenio_device_printf(xenio_device_t *device,
		    const char *key, int mkread, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = xenio_device_vprintf(device, key, mkread, fmt, ap);
	va_end(ap);

	return err;
}

static long long
xenio_device_check_serial(xenio_device_t *device)
{
	long long serial;
	int n, err;

	n = xenio_device_scanf(device, "xenio-serial",
			       "%lld", &serial);
	if (n != 1) {
		err = -EEXIST;
		goto fail;
	}

	if (serial != device->serial) {
		err = -EXDEV;
		goto fail;
	}

	err = 0;
fail:
	return err;
}

static void
xenio_device_unwatch_frontend_state(xenio_device_t *device)
{
	xenio_backend_t *backend = device->backend;

	if (device->frontend_state_path)
		xs_unwatch(backend->xs,
			   device->frontend_state_path, "otherend-state");

	if (device->frontend_state_path) {
		free(device->frontend_state_path);
		device->frontend_state_path = NULL;
	}
}

static int
xenio_device_watch_frontend_state(xenio_device_t *device)
{
	xenio_backend_t *backend = device->backend;
	bool nerr;
	int err;

	device->frontend_state_path = mprintf("%s/state",
					      device->frontend_path);
	if (!device->frontend_state_path) {
		err = -errno;
		goto fail;
	}

	DBG("watching %s\n", device->frontend_state_path);

	nerr = xs_watch(backend->xs,
			device->frontend_state_path, "otherend-state");
	if (!nerr) {
		err = -errno;
		goto fail;
	}

	return 0;

fail:
	xenio_device_unwatch_frontend_state(device);
	return err;
}

static void
xenio_device_check_frontend_state(xenio_device_t *device)
{
	xenio_backend_t *backend = device->backend;
	int state;
	char *s, *end;

	s = xenio_xs_read(backend->xs, backend->xst,
			  "%s",device->frontend_state_path);
	if (!s) {
		goto fail;
	}

	state = strtol(s, &end, 0);
	if (*end != 0 || end == s) {
		goto fail;
	}

	backend->ops->frontend_changed(device, state);

fail:
	return;
}

int
xenio_device_switch_state(xenio_device_t *device, XenbusState state)
{
	return xenio_device_printf(device, "state", 0, "%u", state);
}

static void
xenio_backend_destroy_device(xenio_backend_t *backend,
			     xenio_device_t *device)
{
	list_del(&device->backend_entry);

	xenio_device_unwatch_frontend_state(device);

	if (device->frontend_path) {
		free(device->frontend_path);
		device->frontend_path = NULL;
	}

	if (device->name) {
		free(device->name);
		device->name = NULL;
	}

	free(device);
}

static void
xenio_backend_remove_device(xenio_backend_t *backend,
			    xenio_device_t *device)
{
	backend->ops->remove(device);
	xenio_backend_destroy_device(backend, device);
}


static int
xenio_backend_create_device(xenio_backend_t *backend,
			    int domid, const char *name)
{
	xenio_device_t *device;
	int err;

	device = calloc(1, sizeof(*device));
	if (!device) {
		err = -errno;
		goto fail;
	}

	device->backend        = backend;
	device->serial         = backend->serial++;
	device->domid          = domid;

	list_add_tail(&device->backend_entry,
		      &backend->devices);

	device->name = strdup(name);
	if (!device->name) {
		err = -errno;
		goto fail;
	}

	device->frontend_path = xenio_device_read(device, "frontend");
	DBG("frontend = '%s' (%d)\n", device->frontend_path, errno);
	if (!device->frontend_path) {
		err = -errno;
		goto fail;
	}

	err = xenio_device_printf(device, "xenio-serial", 0,
				  "%lld", device->serial);
	if (err)
		goto fail;

	err = backend->ops->probe(device, device->domid, name);
	if (err)
		goto fail;

	err = xenio_device_watch_frontend_state(device);
	if (err)
		goto fail;

	return 0;

fail:
	if (device) {
		printf("failed: domid=%d name=%s err=%d (%s)\n",
		       device->domid, device->name, err, strerror(-err));
		xenio_backend_destroy_device(backend, device);
	}

	return err;
}

static bool
xenio_backend_device_exists(xenio_backend_t *backend,
			    int domid, const char *name)
{
	return xenio_xs_exists(backend->xs, backend->xst,
			       "%s/%d/%s",
			       backend->path, domid, name);
}

#define xenio_backend_find_device(_backend, _device, _cond)		\
do {									\
	xenio_device_t *__next;					\
	xenio_backend_for_each_device(_device, __next, _backend) {	\
		if (_cond)						\
			break;						\
	}								\
	if (_device == list_entry(&(_backend)->devices,		\
				  xenio_device_t, backend_entry))	\
		_device = NULL;					\
} while (0)

static int
xenio_backend_probe_device(xenio_backend_t *backend,
			   int domid, const char *name)
{
	bool exists, create, remove;
	xenio_device_t *device;
	int err;

	DBG("probe domid=%d name=%s\n", domid, name);

	exists = xenio_backend_device_exists(backend, domid, name);

	xenio_backend_find_device(backend, device,
				  device->domid == domid &&
				  !strcmp(device->name, name));

	remove = device && !exists;
	create = exists && !device;

	DBG("exists=%d device=%p remove=%d create=%d\n",
	    exists, device, remove, create);

	if (device && exists)
		/*
		 * check the device serial, to sync with fast
		 * remove/re-create cycles.
		 */
		remove = create =
			!!xenio_device_check_serial(device);

	if (remove)
		xenio_backend_remove_device(backend, device);

	if (create) {
		err = xenio_backend_create_device(backend, domid, name);
		if (err)
			goto fail;
	}

	err = 0;
fail:
	return err;
}

void
xenio_backend_scan(xenio_backend_t *backend)
{
	xenio_device_t *device, *next;
	unsigned int i, j, n, m;
	char **dir;

	/*
	 * scrap all nonexistent devices
	 */

	xenio_backend_for_each_device(device, next, backend)
		xenio_backend_probe_device(backend,
					   device->domid, device->name);

	/*
	 * probe the new ones
	 */

	dir = xs_directory(backend->xs, backend->xst, backend->path, &n);
	if (!dir)
		return;

	for (i = 0; i < n; i++) {
		char *path, **sub, *end;
		int domid;

		domid = strtoul(dir[i], &end, 0);
		if (*end != 0 || end == dir[i])
			continue;

		path = mprintf("%s/%d", backend->path, domid);
		assert(path != NULL);

		sub = xs_directory(backend->xs, backend->xst, path, &m);
		free(path);

		for (j = 0; j < m; j++)
			xenio_backend_probe_device(backend, domid, sub[j]);

		free(sub);
	}

	free(dir);
}

int
xenio_backend_handle_otherend_watch(xenio_backend_t *backend, char *path)
{
	xenio_device_t *device;

	xenio_backend_find_device(backend, device,
				  !strcmp(device->frontend_state_path, path));
	if (device) {
		DBG("device: domid=%d name=%s\n", device->domid, device->name);
		xenio_device_check_frontend_state(device);
	}

	return 0;
}

int
xenio_backend_handle_backend_watch(xenio_backend_t *backend, char *path)
{
	char *s, *end, *name;
	int domid;

	s = strtok(path, "/");
	assert(!strcmp(s, "backend"));

	s = strtok(NULL, "/");
	if (!s)
		goto scan;

	assert(!strcmp(s, backend->name));

	s = strtok(NULL, "/");
	if (!s)
		goto scan;

	domid = strtoul(s, &end, 0);
	if (*end != 0 || end == s)
		return -EINVAL;

	name = strtok(NULL, "/");
	if (!name)
		goto scan;

	return xenio_backend_probe_device(backend, domid, name);

scan:
	xenio_backend_scan(backend);
	return 0;
}

void
xenio_backend_read_watch(xenio_backend_t *backend)
{
	char **watch, *path, *token;
	unsigned int n;
	int err, _abort;

	watch = xs_read_watch(backend->xs, &n);
	path  = watch[XS_WATCH_PATH];
	token = watch[XS_WATCH_TOKEN];

	DBG("--\n");
	DBG("path=%s token=%s\n", path, token);

again:
	backend->xst = xs_transaction_start(backend->xs);
	if (!backend->xst)
		goto fail;

	switch (token[0]) {
	case 'o':
		if (!strcmp(token, "otherend-state")) {
			err = xenio_backend_handle_otherend_watch(backend,
								  path);
			break;
		}
		BUG();

	case 'b':
		if (!strcmp(token, backend->token)) {
			err = xenio_backend_handle_backend_watch(backend,
								 path);
			break;
		}
		BUG();

	default:
		BUG();
	}

	_abort = !!err;
	if (_abort)
		DBG("aborting transaction: err=%d\n", err);

	err = xs_transaction_end(backend->xs, backend->xst, _abort);
	if (err) {
		err = -errno;
		if (err == EAGAIN)
			goto again;
	}

fail:
	if (watch)
		free(watch);
	return;
}

int
xenio_backend_fd(xenio_backend_t *backend)
{
	return xs_fileno(backend->xs);
}

void
xenio_backend_destroy(xenio_backend_t *backend)
{
	if (backend->token) {
		free(backend->token);
		backend->token = NULL;
	}

	if (backend->path) {
		free(backend->path);
		backend->path = NULL;
	}

	if (backend->name) {
		free(backend->name);
		backend->name = NULL;
	}

	if (backend->xs) {
		xs_daemon_close(backend->xs);
		backend->xs = NULL;
	}

	free(backend);
}

xenio_backend_t *
xenio_backend_create(const char *name, const struct xenio_backend_ops *ops)
{
	xenio_backend_t *backend = NULL;
	bool nerr;
	int err = -EINVAL;

	if (!name)
		goto fail;

	if (strchr(name, '/'))
		goto fail;

	if (!ops)
		goto fail;

	backend = calloc(1, sizeof(*backend));
	if (!backend) {
		err = -errno;
		goto fail;
	}

	INIT_LIST_HEAD(&backend->devices);
	backend->xst = XBT_NULL;

	backend->xs = xs_daemon_open();
	if (!backend->xs) {
		err = -EINVAL;
		goto fail;
	}

	backend->name = strdup(name);
	if (!backend->name) {
		err = -errno;
		goto fail;
	}

	backend->path = mprintf("backend/%s", backend->name);
	if (!backend->path) {
		err = -ENOMEM;
		goto fail;
	}

	backend->token = mprintf("backend-%s", backend->name);
	if (!backend->token) {
		err = -ENOMEM;
		goto fail;
	}

	nerr = xs_watch(backend->xs, backend->path, backend->token);
	if (!nerr) {
		err = -errno;
		goto fail;
	}

	backend->ops = ops;

	return backend;

fail:
	if (backend)
		xenio_backend_destroy(backend);

	errno = -err;
	return NULL;
}

#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include <xen/grant_table.h>
#include <xen/event_channel.h>

#include "blktap2.h"
#include "tap-ctl.h"
#include "tap-ctl-xen.h"

static int blktap_major;

typedef struct blkback_device blkback_device_t;

struct blkback_device {
	dev_t                           dev;

	domid_t                         domid;
	int                             devid;

	grant_ref_t                     gref;
	evtchn_port_t                   port;

	tap_list_t                      tap;

	unsigned int                    sector_size;
	unsigned long long              sectors;
	unsigned int                    info;
};

static int
blkback_find_tapdisk(blkback_device_t *bdev)
{
	struct list_head list;
	tap_list_t *tap;
	int err;

	err = tap_ctl_list(&list);
	if (err)
		return err;

	tap_list_for_each_entry(tap, &list)
		if (tap->minor == minor(bdev->dev))
			break;

	if (tap == list_entry(&list, tap_list_t, entry))
		return -ENOENT;

	memcpy(&bdev->tap, tap, sizeof(bdev->tap));

	return 0;
}

static int
blkback_read_otherend_proto(xenio_device_t *xbdev)
{
	char *s;

	s = xenio_device_read_otherend(xbdev, "protocol");
	if (!s)
		return XENIO_BLKIF_PROTO_NATIVE;

	switch (s[0]) {
	case 'x':
		if (!strcmp(s, "x86_32-abi"))
			return XENIO_BLKIF_PROTO_X86_32;

		if (!strcmp(s, "x86_64-abi"))
			return XENIO_BLKIF_PROTO_X86_64;
	}

	return -EINVAL;
}

void
blkback_connect_tap(xenio_device_t *xbdev)
{
	blkback_device_t *bdev = xbdev->private;
	evtchn_port_t port;
	grant_ref_t gref;
	int n, proto, err;
	char *pool;

	n = xenio_device_scanf_otherend(xbdev, "ring-ref",
					"%u", &gref);
	if (n != 1)
		goto fail;

	n = xenio_device_scanf_otherend(xbdev, "event-channel",
					"%u", &port);
	if (n != 1)
		goto fail;

	proto = blkback_read_otherend_proto(xbdev);
	if (proto < 0)
		goto fail;

	pool = xenio_device_read(xbdev, "sm-data/frame-pool");

	err = blkback_find_tapdisk(bdev);
	if (err)
		goto fail;

	DBG("connecting vbd-%d-%d (gnt %d, evt %d, proto %d, pool %s)"
	    " to tapdisk %d minor %d\n",
	    bdev->domid, bdev->devid,
	    gref, port, proto, pool,
	    bdev->tap.pid, bdev->tap.minor);

	err = tap_ctl_connect_xenblkif(bdev->tap.pid,
				       bdev->tap.minor,
				       bdev->domid,
				       bdev->devid,
				       &gref, 0,
				       port, proto);
	DBG("err=%d errno=%d\n", err, errno);
	if (err)
		goto fail;

	bdev->gref = gref;
	bdev->port = port;

	err = xenio_device_printf(xbdev, "sector-size", 1,
				  "%u", bdev->sector_size);
	if (err)
		goto fail;

	err = xenio_device_printf(xbdev, "sectors", 1,
				  "%llu", bdev->sectors);
	if (err)
		goto fail;

	err = xenio_device_printf(xbdev, "info", 1,
				  "%u", bdev->info);
	if (err)
		goto fail;

	xenio_device_switch_state(xbdev, XenbusStateConnected);

fail:
	return;
}

void
blkback_disconnect_tap(xenio_device_t *xbdev)
{
	blkback_device_t *bdev = xbdev->private;
	int err;

	if (bdev->gref < 0 || bdev->port < 0)
		return;

	DBG("disconnecting vbd-%d-%d from tapdisk %d minor %d\n",
	    bdev->domid, bdev->devid, bdev->tap.pid, bdev->tap.minor);

	err = tap_ctl_disconnect_xenblkif(bdev->tap.pid,
					  bdev->tap.minor,
					  bdev->domid,
					  bdev->devid,
					  NULL);
	if (err && errno != -ESRCH)
		goto fail;

	bdev->gref = -1;
	bdev->port = -1;

	xenio_device_switch_state(xbdev, XenbusStateClosed);
fail:
	return;
}

static int
blkback_probe_device(xenio_device_t *xbdev, const char *path)
{
	blkback_device_t *bdev = xbdev->private;
	uint64_t size64;
	int fd = -1, err;

	DBG("probe device %s\n", path);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		goto fail;
	}

	err = ioctl(fd, BLKSSZGET, &bdev->sector_size);
	if (err) {
		err = -errno;
		goto fail;
	}

	err = ioctl(fd, BLKGETSIZE64, &size64);
	if (err) {
		err = -errno;
		goto fail;
	}

	bdev->sectors = size64 / bdev->sector_size;

	DBG("sectors=%llu sector-size=%d\n",
	    bdev->sectors, bdev->sector_size);

	err = 0;
fail:
	if (fd >= 0)
		close(fd);

	return err;
}

static int
blkback_probe_tapdev(xenio_device_t *xbdev, dev_t dev)
{
	blkback_device_t *bdev = xbdev->private;
	char *path = NULL;
	int err;

	DBG("dev=%d:%d blktap_major=%d\n",
	    major(dev), minor(dev), blktap_major);

	if (major(dev) != blktap_major) {
		err = -EINVAL;
		goto fail;
	}

	path = mprintf(BLKTAP2_IO_DEVICE"%d", minor(dev));
	if (!path) {
		err = -errno;
		goto fail;
	}

	err = blkback_probe_device(xbdev, path);
	if (err)
		goto fail;

	bdev->dev = dev;
	err = 0;

fail:
	if (path)
		free(path);

	return err;
}


static void
blkback_device_destroy(blkback_device_t *bdev)
{
	free(bdev);
}

static int
blkback_probe(xenio_device_t *xbdev, domid_t domid, const char *name)
{
	blkback_device_t *bdev;
	int n, major, minor, err;
	char *end;

	DBG("probe %s-%d-%s\n",
	    xbdev->backend->name, xbdev->domid, xbdev->name);

	bdev = calloc(1, sizeof(*bdev));
	if (!bdev) {
		err = -errno;
		goto fail;
	}
	xbdev->private = bdev;

	bdev->domid = domid;
	bdev->devid = strtoul(name, &end, 0);
	if (*end != 0 || end == name) {
		err = -EINVAL;
		goto fail;
	}

	DBG("devid=%d\n", bdev->devid);

	n = xenio_device_scanf(xbdev, "physical-device",
			       "%x:%x", &major, &minor);
	if (n != 2) {
		err = -ENXIO;
		goto fail;
	}

	DBG("major=%x minor=%x\n", major, minor);

	err = blkback_probe_tapdev(xbdev, makedev(major, minor));
	if (err)
		goto fail;

	DBG("got %s-%d-%d with tapdev %d %d\n",
	    xbdev->backend->name, xbdev->domid,
	    bdev->devid, bdev->tap.pid, bdev->tap.minor);

	return 0;

fail:
	if (bdev)
		blkback_device_destroy(bdev);

	return err;
}

void
blkback_remove(xenio_device_t *xbdev)
{
	blkback_device_t *bdev = xbdev->private;

	DBG("remove %s-%d-%s\n",
	    xbdev->backend->name, xbdev->domid, xbdev->name);

	blkback_device_destroy(bdev);
}

void
blkback_frontend_changed(xenio_device_t *xbdev, XenbusState state)
{
	DBG("frontend_changed %s-%d-%s state=%d\n",
	    xbdev->backend->name, xbdev->domid, xbdev->name, state);

	switch (state) {
	case XenbusStateUnknown:
		/* wtf */
		break;

	case XenbusStateInitialising:
		xenio_device_switch_state(xbdev,
					  XenbusStateInitWait);
		break;

	case XenbusStateInitialised:
	case XenbusStateConnected:
		blkback_connect_tap(xbdev);
		break;

	case XenbusStateClosing:
		xenio_device_switch_state(xbdev,
					  XenbusStateClosing);
		break;

	case XenbusStateClosed:
		blkback_disconnect_tap(xbdev);
		break;

	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
		/* wtf */
		break;

	case XenbusStateInitWait:
		/* fatal */
		break;
	}
}

struct xenio_backend_ops blkback_ops = {
	.probe            = blkback_probe,
	.remove           = blkback_remove,
	.frontend_changed = blkback_frontend_changed,
};

static xenio_backend_t *
blkback_create(const char *name)
{
	blktap_major = tap_ctl_blk_major();
	if (blktap_major < 0)
		return NULL;

	return xenio_backend_create(name, &blkback_ops);
}

static void
blkback_destroy(xenio_backend_t *backend)
{
	xenio_backend_destroy(backend);
}

static int
blkback_run(xenio_backend_t *backend)
{
	int fd, err;

	fd = xenio_backend_fd(backend);

	do {
		fd_set rfds;
		int nfds;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		nfds = select(fd + 1, &rfds, NULL, NULL, NULL);
		if (nfds < 0) {
			perror("select");
			err = -errno;
			break;
		}

		if (FD_ISSET(fd, &rfds))
			xenio_backend_read_watch(backend);
	} while (1);

	return err;
}

static char *blkback_ident;

static void
blkback_vlog_fprintf(int prio, const char *fmt, va_list ap)
{
	const char *strprio[] = {
		[LOG_DEBUG]   = "DBG",
		[LOG_INFO]    = "INF",
		[LOG_WARNING] = "WRN"
	};

	BUG_ON(prio < 0);
	BUG_ON(prio > sizeof(strprio)/sizeof(strprio[0]));
	BUG_ON(!strprio[prio]);

	fprintf(stderr, "%s[%s] ", blkback_ident, strprio[prio]);
	vfprintf(stderr, fmt, ap);
}

static void
usage(FILE *stream, const char *prog)
{
	fprintf(stream,
		"usage: %s\n"
		"        [-n|--name <name>]\n"
		"        [-D|--debug]\n"
		"        [-h|--help]\n", prog);
}

int
main(int argc, char **argv)
{
	xenio_backend_t *backend;
	const char *prog;
	const char *opt_name;
	int opt_debug;
	int err;

	prog = basename(argv[0]);

	opt_debug = 0;
	opt_name  = "vbd";

	do {
		const struct option longopts[] = {
			{"help",        0, NULL, 'h'},
			{"name",        1, NULL, 'n'},
			{"debug",       0, NULL, 'D'},
		};
		int c;

		c = getopt_long(argc, argv, "hn:D", longopts, NULL);
		if (c < 0)
			break;

		switch (c) {
		case 'h':
			usage(stdout, prog);
			return 0;
		case 'n':
			opt_name = optarg;
			break;
		case 'D':
			opt_debug = 1;
			break;
		case '?':
			goto usage;
		}
	} while (1);

	blkback_ident = mprintf("backend-%s", opt_name);
	if (opt_debug)
		xenio_vlog = blkback_vlog_fprintf;
	else
		openlog(blkback_ident, 0, LOG_DAEMON);

	backend = blkback_create(opt_name);
	if (!backend) {
		err = -errno;
		goto fail;
	}

	if (!opt_debug) {
		err = daemon(0, 0);
		if (err) {
			err = -errno;
			goto fail;
		}
	}

	err = blkback_run(backend);

	blkback_destroy(backend);

fail:
	return err ? -err : 0;

usage:
	usage(stderr, prog);
	return 1;
}
