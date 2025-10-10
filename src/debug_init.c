
#include "config.h"




//#include "StdAfx.h"
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
	int truesize;
	int retvalue = 0;
/*	debug_read_proc_file(0);
	//fprintf(stderr,"debugheapstart = %llx, debugheapend = %llx, debugstackstart = %llx, debugstackend = %llx\n",debugheapstart, debugheapend, debugstackstart, debugstackend);
	//exit(EXIT_FAILURE);
	truesize = sizeof(debug_flag) / sizeof(debug_flag[0]);
	if (truesize != NUMDEBUGFLAGS) {
		fprintf(stderr, "bad dimention on debug_flag array, true size = %i, NUMDEBUGFLAGS = %i\n", truesize, NUMDEBUGFLAGS);
		retvalue++;
	}
	truesize = sizeof(bdebug_flag_set) / sizeof(bdebug_flag_set[0]);
	if (truesize != NUMDEBUGFLAGS) {
		fprintf(stderr, "bad dimention on bdebug_flag_set array, true size = %i, NUMDEBUGFLAGS = %i\n", truesize, NUMDEBUGFLAGS);
		retvalue += 2;
	}
	if (retvalue) return(retvalue);
	//char str[LENTEMPSTR];
	//char tmpstr[LENTEMPSTR];

	 */
	strjk = (char*)malloc(LENTEMPSTR);
	tmpstrjk = (char*)malloc(LENTEMPSTR);
	//bOutputDP = bIsStdinTty = isatty(STDIN_FILENO);
	return(0);
}

