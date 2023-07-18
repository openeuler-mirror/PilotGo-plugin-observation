#ifndef _JSON_WRITER_H_
#define _JSON_WRITER_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <linux/compiler.h>


typedef struct json_writer json_writer_t;


json_writer_t *jsonw_new(FILE *f);

void jsonw_destroy(json_writer_t **self_p);

void jsonw_pretty(json_writer_t *self, bool on);

void jsonw_start_array(json_writer_t *self);

void jsonw_start_object(json_writer_t *self);

void jsonw_name(json_writer_t *self, const char *name);

void __printf(2, 3) jsonw_printf(json_writer_t *self, const char *fmt, ...);