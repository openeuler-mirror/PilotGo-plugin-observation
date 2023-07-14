// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Routines for dealing with .zip archives.
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libbpf_internal.h"
#include "zip.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"

/* Specification of ZIP file format can be found here:
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 * For a high level overview of the structure of a ZIP file see
 * sections 4.3.1 - 4.3.6.
 *
 * Data structures appearing in ZIP files do not contain any
 * padding and they might be misaligned. To allow us to safely
 * operate on pointers to such structures and their members, we
 * declare the types as packed.
 */

#define END_OF_CD_RECORD_MAGIC 0x06054b50

/* See section 4.3.16 of the spec. */
struct end_of_cd_record {
	/* Magic value equal to END_OF_CD_RECORD_MAGIC */
	__u32 magic;

	/* Number of the file containing this structure or 0xFFFF if ZIP64 archive.
	 * Zip archive might span multiple files (disks).
	 */
	__u16 this_disk;

	/* Number of the file containing the beginning of the central directory or
	 * 0xFFFF if ZIP64 archive.
	 */
	__u16 cd_disk;

	/* Number of central directory records on this disk or 0xFFFF if ZIP64
	 * archive.
	 */
	__u16 cd_records;

	/* Number of central directory records on all disks or 0xFFFF if ZIP64
	 * archive.
	 */
	__u16 cd_records_total;

	/* Size of the central directory record or 0xFFFFFFFF if ZIP64 archive. */
	__u32 cd_size;

	/* Offset of the central directory from the beginning of the archive or
	 * 0xFFFFFFFF if ZIP64 archive.
	 */
	__u32 cd_offset;

	/* Length of comment data following end of central directory record. */
	__u16 comment_length;

	/* Up to 64k of arbitrary bytes. */
	/* uint8_t comment[comment_length] */
} __attribute__((packed));

#define CD_FILE_HEADER_MAGIC 0x02014b50
#define FLAG_ENCRYPTED (1 << 0)
#define FLAG_HAS_DATA_DESCRIPTOR (1 << 3)

/* See section 4.3.12 of the spec. */
struct cd_file_header {
	/* Magic value equal to CD_FILE_HEADER_MAGIC. */
	__u32 magic;
	__u16 version;
	/* Minimum zip version needed to extract the file. */
	__u16 min_version;
	__u16 flags;
	__u16 compression;
	__u16 last_modified_time;
	__u16 last_modified_date;
	__u32 crc;
	__u32 compressed_size;
	__u32 uncompressed_size;
	__u16 file_name_length;
	__u16 extra_field_length;
	__u16 file_comment_length;
	/* Number of the disk where the file starts or 0xFFFF if ZIP64 archive. */
	__u16 disk;
	__u16 internal_attributes;
	__u32 external_attributes;
	/* Offset from the start of the disk containing the local file header to the
	 * start of the local file header.
	 */
	__u32 offset;
} __attribute__((packed));
