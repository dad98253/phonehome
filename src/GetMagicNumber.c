#ifdef DEBUG
#include "config.h"

#include "lindows.h"
#define dfprintf if (debugflag) WinFprintf

#include <stdio.h>
#ifdef WINDOZE
#include <windows.h>
#include <cderr.h>
#endif

#ifndef PROCESSOR_ARCHITECTURE_AMD64
#define PROCESSOR_ARCHITECTURE_AMD64 9
#endif

#include <assert.h>
#include <string.h>

#include "debug2.h"

#ifdef DEBUG
extern int OpenTCPport(void);
extern int SetUpDebugConsole(void);
extern int IPSend(char * data, int MaxDataSize);
extern int ClosePort(void);
extern short BWError(HWND hwnd, WORD bFlags, WORD quit, WORD id, ...);
extern int ReAllocateCharVector(unsigned char **p, int length);
extern void	DumpRamFile(FILE *hp,char **lpHeapFile);
void Replace_ws_With_s(const char * fmt, char * tempstr);
extern int debugCheckflags(unsigned int debugflag);
extern char* strjk;
extern char* tmpstrjk;
char * lpDebugOutputFileName = NULL;
int hWnd = 0;
#define IDS_ABORT	1
int iStartOfHeapFile;

#endif

#define MAGIC_NUMBER 950.0F
#ifndef bool
    #define bool int
    #define false ((bool)0)
    #define true  ((bool)1)
#endif

#ifdef DEBUG
bool SaveStringInHeap(char **lpHeapFile,char *str);
extern bool StripCSI(char *ci, char *co);
#endif

#if defined(DEBUG)
bool fDebug = TRUE;
#endif

bool bMyWay = true;
HANDLE hCom;
FILE *hpfile = NULL;
#define FILEOUTPUT 0
#define SERIALPORT 1
#define CONSOLE    2
#define TCPPORT    3
#define BITBUCKET  4
#define DEBUGWIN   5
#define RAM		   6


int iDebugOutputDevice = TCPPORT;
char * lpHeapFile;
int ColorDebug = 1;
int debugflag = 0;


int FAR cdecl WinPrintf(LPSTR fmt,...)
{
va_list args;
char str[250];
int nTmp;

    va_start(args, fmt);
	if ( !bMyWay ) return -1;
    nTmp=vsprintf(str,fmt,args);
	assert(nTmp<250);
	switch (iDebugOutputDevice)
      {
   	  case TCPPORT:
#ifdef DEBUG
		IPSend(str, strlen(str)+1);	
#endif
		break;

	  case RAM:
		SaveStringInHeap(&lpHeapFile,str);
#ifdef PRINTFDEBUG
		fprintf(stderr,"%s",str);
#endif
		break;
	}

    va_end(args);
    return(nTmp);
}

int FAR cdecl WinFprintf(FILE *hf, const char * fmt,...)
{
va_list args;
#define LENTEMPSTR	10000
char str[LENTEMPSTR];
char tmpstr[LENTEMPSTR];
int nTmp;

    va_start(args, fmt);
	if ( !bMyWay ) return -1;
#ifdef WINDOZE
    nTmp=vsprintf(str,fmt,args);
#else
	Replace_ws_With_s(fmt,tmpstr);
    nTmp=vsprintf(str,tmpstr,args);
#endif
	assert(nTmp<LENTEMPSTR);
	switch (iDebugOutputDevice)
      {

	  case TCPPORT:
#ifdef DEBUG
		if ( !ColorDebug ) {
			strcpy(tmpstr,str);
			StripCSI(tmpstr,str);
		}
		IPSend(str, strlen(str)+1);	
#endif
		break;

	  case RAM:
		SaveStringInHeap(&lpHeapFile,str);
#ifdef PRINTFDEBUG
		fprintf(stderr,"%s",str);
#endif
		break;
	}

    va_end(args);
    return(nTmp);
}


int Dbgprintf(int linenum, const char * modulename, unsigned int debugflag, const char * fmt,...)
{
va_list args;

	int nTmp;

    va_start(args, fmt);

	if ( debugCheckflags( (unsigned int)debugflag ) == 0) return(0);
	strjk[0]='\000';
	tmpstrjk[0]='\000';
	nTmp=vsprintf(tmpstrjk,fmt,args);
	assert(nTmp<LENTEMPSTR);
	if ( debugflag >= NOHEADspecial ) {
		nTmp=sprintf(strjk,"%s",tmpstrjk);
	} else {
		nTmp=sprintf(strjk,DBGBOLDGREEN(line) " " DBGBOLDRED(%i) " " DBGBOLDGREEN(in) " " DBGBOLDRED(%s) ": %s",linenum,modulename,tmpstrjk);
	}
	assert(nTmp<LENTEMPSTR);
	switch (iDebugOutputDevice)
      {


	  case TCPPORT:

		if ( !ColorDebug ) {
			strcpy(tmpstrjk,strjk);
			StripCSI(tmpstrjk,strjk);
		}
		IPSend(strjk, strlen(strjk)+1);

		break;

	  case RAM:
		SaveStringInHeap(&lpHeapFile,strjk);
		dfprintf2(__LINE__,__FILE__,DEBUGDBGPRINTF,"%s",strjk);

		break;
	}

    va_end(args);
    return(nTmp);
}


int OpenDebugDevice(FILE **hp)
{

#define LENTEMPLINE	250

	SaveStringInHeap(&lpHeapFile,(char*)"$e$n$d$o$f$f$i$l$e$");

	switch (iDebugOutputDevice)
      {

	  case TCPPORT:
#ifdef DEBUG
			if (OpenTCPport()==0) return 0;
#endif
			break;

	  case BITBUCKET:
	  case DEBUGWIN:
	  case RAM:
			break;

	}

	DumpRamFile(*hp,&lpHeapFile);

    return 1;
}

int CloseDebugDevice(FILE *hp)
{

	switch (iDebugOutputDevice)
      {


	  case TCPPORT:
#ifdef DEBUG
		ClosePort();
#endif
		break;

	  case BITBUCKET:
  	  case DEBUGWIN:
	  case RAM:
		break;
	}
	return 1;
}

bool SaveStringInHeap(char **lpHeapFile,char *str)
{
	int istart;
	int iend;
#ifdef DEBUGSAVEINSTRING2
printf("save \"%s\" *lpHeapFile=(0x%p)\n",str,(void*)*lpHeapFile);
#endif
	istart = ReAllocateCharVector((unsigned char **)lpHeapFile, 0);
	if ( istart == 1 ) {
		**lpHeapFile = '\n';
		iStartOfHeapFile++;
	}
	if ( istart < (iStartOfHeapFile + (int)strlen(str) + 2)) {
		iend   = ReAllocateCharVector((unsigned char **)lpHeapFile, strlen(str)+1 );
		if (iend == 0) {
			fprintf(stderr,"realloc failed in SaveStringInHeap\n");
			return (true);
		}
	}
#ifdef DEBUGSAVEINSTRING2
printf("save string at (0x%p)+%i of length %i\n",(void*)*lpHeapFile,istart,(int)strlen(str));
#endif
	strcpy(*lpHeapFile+iStartOfHeapFile,str);
	iend = iStartOfHeapFile + strlen(str);
	*(*lpHeapFile+iend) = '\000';
	iStartOfHeapFile+=strlen(str)+1;

	return (false);
}

void DumpRamFile(FILE *hp, char **lpHeapFile)
{
	int istart;
	int iend;

	if (*lpHeapFile == NULL) return;

	istart = 1;
	iend = ReAllocateCharVector((unsigned char **)lpHeapFile, 0);

	while ( istart < iend )
	{
		if (strcmp( ((*lpHeapFile)+istart) , "$e$n$d$o$f$f$i$l$e$" ) == 0 ) goto done;
		dfprintf(hp, ((*lpHeapFile)+istart) );
		istart+= ( strlen( (*lpHeapFile)+istart ) + 1 );
	}

done:
	free(*lpHeapFile);
	*lpHeapFile = NULL;

	return;
}

void Replace_ws_With_s(const char * fmt, char * tempstr)
{
#ifdef DEBUGREPLACEWS
printf("fmt = \"%s\"\n",fmt);
#endif
	int ii = 0;
	int j = 0;
	int slen;
	slen = strlen(fmt);
	while (ii<slen-2){
		if(fmt[ii] == '%' && fmt[ii+1] == 'w' && fmt[ii+2] == 's' ) {
//printf("found percentws at i=%i (%c)\n",ii,fmt[ii]);
			tempstr[j] = fmt[ii];
			j++;
			ii++;
			ii++;
		}
		tempstr[j] = fmt[ii];
		j++;
		ii++;
	}
	tempstr[j] = fmt[ii];
	j++;
	ii++;
	tempstr[j] = fmt[ii];
	j++;
	tempstr[j] = '\000';
	return;
}

#endif	// DEBUG

