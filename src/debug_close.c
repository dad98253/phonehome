
#include "config.h"



//#include "StdAfx.h"
#include <malloc.h>

extern char * strjk;
extern char * tmpstrjk;

void debug_close() {
	free(strjk);
	free(tmpstrjk);
	//CloseDebugDevice();
	return;
}

