#ifndef _UAPI__LINUX_BTF_H__
#define _UAPI__LINUX_BTF_H__

#include <linux/types.h>

#define BTF_MAGIC	0xeB9F
#define BTF_VERSION	1

struct btf_header {
	__u16	magic;
	__u8	version;
	__u8	flags;
	__u32	hdr_len;

	/* All offsets are in bytes relative to the end of this header */
	__u32	type_off;	/* offset of type section	*/
	__u32	type_len;	/* length of type section	*/
	__u32	str_off;	/* offset of string section	*/
	__u32	str_len;	/* length of string section	*/
};