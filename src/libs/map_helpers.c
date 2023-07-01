// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "map_helpers.h"

static bool batch_map_ops = true; /* hope for the best */

static int
dump_hash_iter(int map_fd, void *keys, __u32 key_size,
	       void *values, __u32 value_size, __u32 *count,
	       void *invalid_key)
{
	__u8 key[key_size], next_key[key_size];
	__u32 n = 0;
	int i, err;

	/* First get keys */
	__builtin_memcpy(key, invalid_key, key_size);
	while (n < *count) {
		err = bpf_map_get_next_key(map_fd, key, next_key);
		if (err && errno != ENOENT) {
			return -1;
		} else if (err) {
			break;
		}
		__builtin_memcpy(key, next_key, key_size);
		__builtin_memcpy(keys + key_size * n, next_key, key_size);
		n++;
	}

	/* Now read values */
	for (i = 0; i < n; i++) {
		err = bpf_map_lookup_elem(map_fd, keys + key_size * i,
					  values + value_size * i);
		if (err)
			return -1;
	}

	*count = n;
	return 0;
}

