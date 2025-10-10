
#include "config.h"




//#include "StdAfx.h"
#include "debug2.h"

extern int bMyWay;
extern int MsgBox(const char* fmt, ...);

int debugCheckflags(unsigned int debugflag)
{        
/*	if (!bMyWay) return(0);
	if (debugflag == 0) return(0);
	if (debugflag == HEADUNCOND) return(1);
	if ((debugflag > NUMDEBUGFLAGS&& debugflag < HEADUNCOND) || debugflag > (NOHEADspecial + NUMDEBUGFLAGS)) {
		MsgBox("debugCheckflags failed, \"%u\" is not a valid debug flag number\n debug flag numbers must be less than %u", debugflag, NUMDEBUGFLAGS);
		if (!bdebug_flag_set[BMYWAYOVERRIDE]) bMyWay = false;
		return(0);
	}
	if (debugflag < HEADUNCOND) {
		if (bdebug_flag_set[debugflag]) return(1);
	}
	if (debugflag > NOHEADspecial) {
		if (bdebug_flag_set[debugflag - NOHEADspecial]) return(1);
	}

	return (0);
*/
	return(1);
}


