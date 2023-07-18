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

void jsonw_pretty(json_writer_t *self, bool on)
{
	self->pretty = on;
}

void jsonw_reset(json_writer_t *self)
{
	assert(self->depth == 0);
	self->sep = '\0';
}

void jsonw_start_array(json_writer_t *self)
{
	jsonw_begin(self, '[');
}


void jsonw_start_object(json_writer_t *self)
{
	jsonw_begin(self, '{');
}

void jsonw_name(json_writer_t *self, const char *name)
{
	jsonw_eor(self);
	jsonw_eol(self);
	self->sep = '\0';
	jsonw_puts(self, name);
	putc(':', self->out);
	if (self->pretty)
		putc(' ', self->out);
}