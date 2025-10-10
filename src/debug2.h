#pragma once
#ifndef _JOHN_DEBUG_H
#define _JOHN_DEBUG_H

#define LENTEMPSTR	10000

#ifdef DEBUG

//#include <malloc.h>
#define CCALLING
#define DBGLVLTEST	debugVirbosity


#ifndef DEBUGMAIN
#define EXTERN		extern
#define INITIZERO
#define INITSZERO
#define INITBOOLFALSE
#define INITBOOLTRUE
#define INITNULL
#define INITNEGDONE
#else	// DEBUGMAIN
#define EXTERN
#define INITIZERO	=0
#define INITSZERO	={0}
#define INITBOOLFALSE	=false
#define INITBOOLTRUE	=true
#define INITNULL	=NULL
#define INITNEGDONE	=-1
#endif	// DEBUGMAIN


#if __linux__   //  or #if __GNUC__
#if __x86_64__ || __ppc64__
#define DEBUGENVIRONMENT64
#else
#define DEBUGENVIRONMENT32
#endif
#else	// __linux__
#if _WIN32
#define DEBUGENVIRONMENT32
#else	// _WIN32
#define DEBUGENVIRONMENT64
#endif	// _WIN32
#endif // __linux__

#ifdef WINDOZE
#if _MSC_VER > 1500
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif	// _CRTDBG_MAP_ALLOC
EXTERN _CrtMemState heapstate1;
EXTERN _CrtMemState heapstate2;
EXTERN _CrtMemState heapstate3;
#else // _MSC_VER
#include <malloc.h>
#endif // _MSC_VER
#else// WINDOZE
#include <malloc.h>
#endif// WINDOZE

// functions
EXTERN  int debug_init();
//EXTERN  void load_debug();
EXTERN  void debug_close();
//EXTERN  char* jtrbacktrace(int i);
//EXTERN  char* jtrunwind(int icall);
EXTERN  int debug_read_proc_file(int idumpem);
EXTERN  int debugCheckflags(unsigned int debugflag);
EXTERN CCALLING int Dbgprintf(int linenum, const char * modulename, unsigned int debugflag, const char * fmt,...);
EXTERN  unsigned char debugSetDBLevel(int DesiredLevel);


// macros
#define debugstf(x) ( (x) ? (sDebugTrueFalse[1]) : (sDebugTrueFalse[0]) )


// define dfprintf2 command (conditional formatted print to debug device with line number)
#define dfprintf2 if ( DBGLVLTEST > NONE ) Dbgprintf

// define ddfprintf2 command (formatted print to debug device)
#define ddfprintf2 if ( DBGLVLTEST > NONE ) Dbgdmpprintf

// define dcfprintf2 command (conditional formatted print to debug device)
#define dcfprintf2 if ( DBGLVLTEST > NONE ) Dbg2dmpprintf

// define some text colors
#define DBGBOLDBLACK(x)		"\33[1;30m"#x"\33[39m"
#define DBGBOLDRED(x)		"\33[1;31m"#x"\33[39m"
#define DBGBOLDGREEN(x)		"\33[1;32m"#x"\33[39m"
#define DBGBOLDYELLOW(x)	"\33[1;33m"#x"\33[39m"
#define DBGBOLDBLUE(x)		"\33[1;34m"#x"\33[39m"
#define DBGBOLDMAGENTA(x)	"\33[1;35m"#x"\33[39m"
#define DBGBOLDCYAN(x)		"\33[1;36m"#x"\33[39m"
#define DBGBOLDWHITE(x)		"\33[1;37m"#x"\33[39m"
//#define DBGHOMECURSOR		"\33[[H"
//#define DBGCLRSCR		"\33[[2J"
#define DBGHOMECURSOR		"\33[H"
#define DBGHOMECURSORLEN	3
#define DBGCLRSCR		"\33[2J"
#define DBGCLRSCRLEN		4
#define DBGCOLOR2DEFAULT	"\33[39m\33[49m"
#define DBGCOLOR2DEFAULTLEN	10
#define DBGRESETALLATTRIBUTES	"\33[0m"
#define DBGRESETALLATTRIBUTESLEN	4

// types


// variables
#ifndef WINDOZE
EXTERN unsigned long long int debugheapstart INITIZERO;
EXTERN unsigned long long int debugheapend INITIZERO;
EXTERN unsigned long long int debugstackstart INITIZERO;
EXTERN unsigned long long int debugstackend INITIZERO;
#endif	// WINDOZE
EXTERN unsigned char debugVirbosity INITIZERO;
EXTERN unsigned char debugInitialVirbosity INITIZERO;
#ifdef DEBUGMAIN
EXTERN char* sDebugTrueFalse[2] = { (char*)"False" , (char*)"True" };
#else	// DEBUGMAIN
EXTERN char* sDebugTrueFalse[2];
#endif	// DEBUGMAIN

// If ColorDebug is set to true (non-zero), the debug output device is assumed to interpret ansi escape
// codes and debug output will be colorized.
// If ColorDebug is zero (default) no ansi escape sequences will be sent to the debug output device.
//EXTERN int ColorDebug INITIZERO;		// defined in passwordsW



#endif  // DEBUG

// define debug option indecies
#define	NONE	0
#define	NEVER	0
#define OFF	0
#define HEADUNCOND	99998
#define NOHEADspecial	99999
#define TRACE			1
#define DEBUGTUTOR		2
#define HEAPTRACE1		3
//#define DEBUGMSGBOX		4		//  see definition in debugflags.h
#define DEBUGREALLOCATECHAR	5
#define DEBUGOPENTCPPORT	6
#define DEBUGSAVEINSTRING	7
#define DEBUGDBGPRINTF		8
#define DEBUGDUMPRAMFILE	9
#define TRACE2			10
#define DEBUGDYNASALT		11
#define DEBUGSALTDUMP		12
#define DEBUGCUDAMEMCOPY	13
#define DEBUGPROCFILE		14 
#define TRACECUDA		15 
#define DMPFMTMAIN		16 
#define DMPDBMAIN		17
#define DBGREGISTER		18
#define DEBUGVALID		19
#define SETKEYDEBUG		20
#define GETKEYDEBUG		21
#define GETHASHDEBUG		22
#define SETSALTDEBUG		23
#define GETSALTDEBUG		24
#define FMTSELFTESTDEBUG	25
#define DYNASALTDEBUG		26
#define DEBUGDMPSTUFF		27
#define DEBUGINIT		28
#define QUIET			29
#define TRACEJOHNINIT		30
#define TRACEJOHNRUN		31
#define TRACEJOHNLOAD		32
#define TRACEJOHNLOG		33
#define TRACELOADER		34
#define TRACEDYNASALT		35
#define TRACECMPALL		36
#define TRACECMPONE		37
#define TRACECMPEXACT		38
#define TRACECUDADONE		39
#define TRACECUDAINIT		40
#define TRACECUDACRYPTALL	41
#define TRACECRYPTALL		42
#define TRACEISKEY		43
#define TRACEMISC		44
#define FMTSELFTESTDEBUGDMPSALT	45
#define TRACETESTFMTCASE	46
#define TRACEFNTDFLTRESET	47
#define TRACEFNTDFLTSPLIT	48
#define TRACECRACKER		49
#define TRACECRACKER2		50
#define TRACECRACKER3		51
#define TRACECRACKER4		52
#define TRACEBATCH		53
#define TRACESINGLE		54
#define ALLON			55
#define FMTSELFTESTDEBUGDMPFMT	56
#define BMYWAYOVERRIDE		57
#define CUDASHA512ABORT		58

#ifdef DEBUG
// define the size of the debug option arrays
#define NUMDEBUGFLAGS	60
// define debug option names (should set to same as index define name)
#ifndef DEBUGMAIN
EXTERN const char* debug_flag[NUMDEBUGFLAGS];
#else	// DEBUGMAIN
const char* debug_flag[NUMDEBUGFLAGS] = {
	"none", \
	"TRACE", \
	"DEBUGTUTOR", \
	"DEBUGMSIZE", \
	"DEBUGMSGBOX", \
	"DEBUGREALLOCATECHAR", \
	"DEBUGOPENTCPPORT", \
	"DEBUGSAVEINSTRING", \
	"DEBUGDBGPRINTF", \
	"DEBUGDUMPRAMFILE", \
	"TRACE2", \
	"DEBUGDYNASALT", \
	"DEBUGSALTDUMP", \
	"DEBUGCUDAMEMCOPY", \
	"DEBUGPROCFILE", \
	"TRACECUDA", \
	"DMPFMTMAIN", \
	"DMPDBMAIN", \
	"DBGREGISTER", \
	"DEBUGVALID", \
	"SETKEYDEBUG", \
	"GETKEYDEBUG", \
	"GETHASHDEBUG", \
	"SETSALTDEBUG", \
	"GETSALTDEBUG", \
	"FMTSELFTESTDEBUG", \
	"DYNASALTDEBUG", \
	"DEBUGDMPSTUFF", \
	"DEBUGINIT", \
	"QUIET", \
	"TRACEJOHNINIT", \
	"TRACEJOHNRUN", \
	"TRACEJOHNLOAD", \
	"TRACEJOHNLOG", \
	"TRACELOADER", \
	"TRACEDYNASALT", \
	"TRACECMPALL", \
	"TRACECMPONE", \
	"TRACECMPEXACT", \
	"TRACECUDADONE", \
	"TRACECUDAINIT", \
	"TRACECUDACRYPTALL", \
	"TRACECRYPTALL", \
	"TRACEISKEY", \
	"TRACEMISC", \
	"FMTSELFTESTDEBUGDMPSALT", \
	"TRACETESTFMTCASE", \
	"TRACEFNTDFLTRESET", \
	"TRACEFNTDFLTSPLIT", \
	"TRACECRACKER", \
	"TRACECRACKER2", \
	"TRACECRACKER3", \
	"TRACECRACKER4", \
	"TRACEBATCH", \
	"TRACESINGLE", \
	"ALLON", \
	"FMTSELFTESTDEBUGDMPFMT", \
	"BMYWAYOVERRIDE", \
	"CUDASHA512ABORT", \
	"" };

#endif	// DEBUGMAIN
// define the debug option status flags
EXTERN unsigned char bdebug_flag_set[NUMDEBUGFLAGS] INITSZERO;

#else   //    DEBUG

// create dummy dfprintf command for non-debug compiles
#define dfprintf2 if (0) ((int (*)(int, ...)) 0)

// create dummy ddfprintf command for non-debug compiles
#define ddfprintf2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy dcfprintf command for non-debug compiles
#define dcfprintf2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debugstf() and jtrunwind() macros for non-debug compiles
#define debugstf(x) (0)
#define jtrunwind(x) (0)


// create dummy color macros
#define DBGBOLDBLACK(x)		#x
#define DBGBOLDRED(x)		#x
#define DBGBOLDGREEN(x)		#x
#define DBGBOLDYELLOW(x)	#x
#define DBGBOLDBLUE(x)		#x
#define DBGBOLDMAGENTA(x)	#x
#define DBGBOLDCYAN(x)		#x
#define DBGBOLDWHITE(x)		#x
#define DBGHOMECURSOR		""
#define DBGHOMECURSORLEN	0
#define DBGCLRSCR		""
#define DBGCLRSCRLEN		0
#define DBGCOLOR2DEFAULT	""
#define DBGCOLOR2DEFAULTLEN	0
#define DBGRESETALLATTRIBUTES	""
#define DBGRESETALLATTRIBUTESLEN	0

#endif  //    DEBUG
#endif  //    fi _JOHN_DEBUG_H

