/*
 * Copyright (c) 2010, XenSource Inc.
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

#include <stdio.h>
#include <string.h>

#include "tap-ctl.h"
#include "tap-ctl-xen.h"

int
tap_ctl_connect_xenblkif(pid_t pid, int minor,
			 domid_t domid, int devid,
			 const grant_ref_t *grefs, int order,
			 evtchn_port_t port,
			 int proto,
			 const char *pool)
{
	tapdisk_message_t message;
	int i, err;

	memset(&message, 0, sizeof(message));
	message.type   = TAPDISK_MESSAGE_XENBLKIF_CONNECT;
	message.cookie = minor;

	message.u.blkif.domid = domid;
	message.u.blkif.devid = devid;
	for (i = 0; i < 1<<order; i++)
		message.u.blkif.gref[i] = grefs[i];
	message.u.blkif.order = order;
	message.u.blkif.port  = port;
	message.u.blkif.proto = proto;
	strncpy(message.u.blkif.pool, pool, sizeof(message.u.blkif.pool));

	err = tap_ctl_connect_send_and_receive(pid, &message, NULL);
	if (err)
		return err;

	if (message.type == TAPDISK_MESSAGE_XENBLKIF_CONNECT_RSP)
		err = -message.u.response.error;
	else
		err = -EINVAL;

	return err;
}

int
tap_ctl_disconnect_xenblkif(pid_t pid, int minor,
			    domid_t domid, int devid,
			    struct timeval *timeout)
{
	tapdisk_message_t message;
	int err;

	memset(&message, 0, sizeof(message));
	message.type   = TAPDISK_MESSAGE_XENBLKIF_DISCONNECT;
	message.cookie = minor;
	message.u.blkif.domid = domid;
	message.u.blkif.devid = devid;

	err = tap_ctl_connect_send_and_receive(pid, &message, timeout);
	if (message.type == TAPDISK_MESSAGE_XENBLKIF_CONNECT_RSP)
		err = -message.u.response.error;
	else
		err = -EINVAL;

	return err;
}
