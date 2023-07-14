/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Simple streaming JSON writer
 *
 * This takes care of the annoying bits of JSON syntax like the commas
 * after elements
 *
 * Authors:	Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef _JSON_WRITER_H_
#define _JSON_WRITER_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <linux/compiler.h>

/* Opaque class structure */
typedef struct json_writer json_writer_t;

/* Create a new JSON stream */
json_writer_t *jsonw_new(FILE *f);
/* End output to JSON stream */
void jsonw_destroy(json_writer_t **self_p);