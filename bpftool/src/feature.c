#include "main.h"

#ifndef PROC_SUPER_MAGIC
# define PROC_SUPER_MAGIC	0x9fa0
#endif



int do_feature(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
