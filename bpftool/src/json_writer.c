#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <malloc.h>
#include <inttypes.h>
#include <stdint.h>

#include "json_writer.h"

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

static void jsonw_eol(json_writer_t *self)
{
	if (!self->pretty)
		return;

	putc('\n', self->out);
	jsonw_indent(self);
}

static void jsonw_puts(json_writer_t *self, const char *str)
{
	putc('"', self->out);
	for (; *str; ++str)
		switch (*str) {
		case '\t':
			fputs("\\t", self->out);
			break;
		case '\n':
			fputs("\\n", self->out);
			break;
		case '\r':
			fputs("\\r", self->out);
			break;
		case '\f':
			fputs("\\f", self->out);
			break;
		case '\b':
			fputs("\\b", self->out);
			break;
		case '\\':
			fputs("\\\\", self->out);
			break;
		case '"':
			fputs("\\\"", self->out);
			break;
		default:
			putc(*str, self->out);
		}
	putc('"', self->out);
}

static void jsonw_eor(json_writer_t *self)
{
	if (self->sep != '\0')
		putc(self->sep, self->out);
	self->sep = ',';
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

void jsonw_printf(json_writer_t *self, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	jsonw_eor(self);
	vfprintf(self->out, fmt, ap);
	va_end(ap);
}

void jsonw_start_object(json_writer_t *self)
{
	jsonw_begin(self, '{');
}

void jsonw_bool(json_writer_t *self, bool val)
{
	jsonw_printf(self, "%s", val ? "true" : "false");
}

void jsonw_bool_field(json_writer_t *self, const char *prop, bool val)
{
	jsonw_name(self, prop);
	jsonw_bool(self, val);
}

void jsonw_end_object(json_writer_t *self)
{
	jsonw_end(self, '}');
}

void jsonw_end_array(json_writer_t *self)
{
	jsonw_end(self, ']');
}