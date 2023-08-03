#include "json_writer.h"
#include "main.h"

int do_btf(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
