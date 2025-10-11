
#include "config.h"


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#define DEBUGMAIN
#include "debug2.h"

extern int debug_read_proc_file(int idumpem);

char * strjk = NULL;
char * tmpstrjk = NULL;

int debug_init()
{

	strjk = (char*)malloc(LENTEMPSTR);
	tmpstrjk = (char*)malloc(LENTEMPSTR);
	//bOutputDP = bIsStdinTty = isatty(STDIN_FILENO);
	return(0);
}

