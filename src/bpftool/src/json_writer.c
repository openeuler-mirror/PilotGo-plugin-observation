// SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)
/*
 * Simple streaming JSON writer
 *
 * This takes care of the annoying bits of JSON syntax like the commas
 * after elements
 *
 * Authors:	Stephen Hemminger <stephen@networkplumber.org>
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <malloc.h>
#include <inttypes.h>
#include <stdint.h>

#include "json_writer.h"

/* Create a new JSON stream */
json_writer_t *jsonw_new(FILE *f)
{
	json_writer_t *self = malloc(sizeof(*self));
	if (self) {
		self->out = f;
		self->depth = 0;
		self->pretty = false;
		self->sep = '\0';
	}
	return self;
}

/* End output to JSON stream */
void jsonw_destroy(json_writer_t **self_p)
{
	json_writer_t *self = *self_p;

	assert(self->depth == 0);
	fputs("\n", self->out);
	fflush(self->out);
	free(self);
	*self_p = NULL;
}

void jsonw_reset(json_writer_t *self)
{
	assert(self->depth == 0);
	self->sep = '\0';
}