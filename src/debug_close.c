#ifdef DEBUG
#include "config.h"

#include <malloc.h>

extern char * strjk;
extern char * tmpstrjk;

void debug_close() {
	free(strjk);
	free(tmpstrjk);
	//CloseDebugDevice();
	return;
}

#endif	// DEBUG
