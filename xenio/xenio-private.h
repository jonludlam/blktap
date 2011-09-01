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

#ifndef _XENIO_PRIVATE_H
#define _XENIO_PRIVATE_H

#include "list.h"

struct xenio_ctx {
	int              xcg_handle;
	int              xce_handle;
	struct list_head ifs;
};

#include <stdlib.h>

#define BUG() abort()
#define ARRAY_SIZE(_a) (sizeof(_a)/sizeof(_a[0]))

#endif /* _XENIO_PRIVATE_H */
