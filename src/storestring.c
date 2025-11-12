#ifdef DEBUG
#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include "lindows.h"
#include "debug2.h"

extern int WinFprintf(FILE *hf, const char * fmt,...);

size_t _msize(
void *memblock
)
{
#ifdef DEBUGMSIZE
	WinFprintf(fp9,"msize = %lu\n", malloc_usable_size (memblock));
#endif
	return (malloc_usable_size (memblock));
}


int storestring(char **p, char * string, int length)
{
	int trueLength = 0;
	trueLength = strlen(string);
	if ( length < trueLength ) trueLength = length;
	*p = (char*)malloc(trueLength+4);
	
	if (*p != NULL) {
		strcpy (*p,string);
		return (0);
	}
	return (1);
}

int AllocatePointerVector(void **p, size_t size, int length)
{
	*p = (void*)calloc((length+1), size);
	
	if (*p != NULL) {
		return (0);
	}
	return (1);
}


int ReAllocatePointerVector(void **p, size_t size, int length)
{

	if ( *p != NULL ) {
		int isize;
		isize = _msize( *p );
		if ( length == 0 ) return (isize);
   /* Reallocate and show new size: */
		if( (*p = realloc( *p, isize + ((length+1) * size) )) ==  NULL ) return (0);
		isize = _msize( *p );
		return (isize);
	}

	*p = (void*)calloc((length+1), size);
	
	if (*p != NULL) {
		return ((length+1)*size);
	}
	return (0);

}

int AllocateCharVector(unsigned char **p, int length)
{
	int i;
	*p = (unsigned char*)malloc(length+4);
	
	if (*p != NULL) {
		for (i=0;i<length;i++){
			*(*p+i) = '\000';
		}
		return (0);
	}
	return (1);
}

int ReAllocateCharVector(db_heapfile_t *p, int length)
{
	int i;
	int isize = 0;

	// if a request for size is made on an uninitialized array, return error
	if ( p->heapfile == NULL && length == 0 ) return 0;
	// loength must be positive
	if ( length < 0 ) return 0;

	if ( p->heapfile != NULL ) {
		isize = _msize( p->heapfile );
	} else {
		isize = 0;
	}

#ifdef DEBUGREALLOCATECHAR
printf( "Size of block (%p) (len=%i) before realloc: %u\n", p->heapfile, length, isize );
#endif
	if ( length == 0 ) return (p->numlines);

/* Reallocate and show new size: */
	i = p->numlines + length + 1;
	if( ( p->heapfile = (char **)realloc( p->heapfile, i * sizeof(*(p->heapfile)) ) ) ==  NULL ) return (0);
	int oldlength = p->numlines;
	p->numlines += length;
	isize = _msize( p->heapfile );
#ifdef DEBUGREALLOCATECHAR
printf( "Size of block (%p) after realloc: %u (requested %i)\n", p->heapfile, isize ,i);
#endif
	for ( i=oldlength; i<(p->numlines); i++) {
		p->heapfile[i] = NULL;
	}

	return (p->numlines);
}

#endif	// DEBUG
