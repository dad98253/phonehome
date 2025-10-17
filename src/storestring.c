#ifdef DEBUG
#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include "lindows.h"


size_t _msize(
void *memblock
)
{
#ifdef DEBUGMSIZE
	dfprintf(fp9,"msize = %lu\n", malloc_usable_size (memblock));
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

int ReAllocateCharVector(unsigned char **p, int length)
{
	int i;
	int isize = 0;

	if ( *p != NULL ) {
		isize = _msize( *p );
#ifdef DEBUGREALLOCATECHAR
printf( "Size of block (%llx) (len=%i) before realloc: %u\n", *p, length, isize );
#endif
		if ( length == 0 ) return (isize);

   /* Reallocate and show new size: */
		i = isize + length + 1;
		if( (*p = (unsigned char*)realloc( *p, i) ) ==  NULL ) return (0);
		isize = _msize( *p );
#ifdef DEBUGREALLOCATECHAR
printf( "Size of block (%llx) after realloc: %u (requested %i)\n", *p, isize ,i);
#endif
		return (isize);
	}


	*p = (unsigned char*)malloc(length+4);
#ifdef DEBUGREALLOCATECHAR
printf( "Address of block (%llx) after malloc: size >= %i\n", *p, length+4 );
#endif
	if (*p != NULL) {
		for (i=0;i<length+4;i++){
			*(*p+i) = '\000';
		}
		return (length+4);
	}
	return (0);
}

#endif	// DEBUG
