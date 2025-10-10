#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  // HAVE_CONFIG_H

#ifndef WINDOZE
//#include "StdAfx.h"
#include "lindows.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RANGE1(x) (((x) > 63 && (x) < 96 ) ? true : false )
#define RANGE2(x) (((x) > 63 && (x) < 127 ) ? true : false )
#ifndef bool
    #define bool int
    #define false ((bool)0)
    #define true  ((bool)1)
#endif


bool StripCSI(char *ci, char *co)
{

    enum stateENUM {
      INITIAL,
      SINGLECHAR,
      TWOCHAR,
      MULTICHAR1,
      MULTICHAR2
    } state = INITIAL;

	enum OutStateENUM {
      OUTPUT,
      NOOUTPUT
    } OutState = OUTPUT;

	static char ESC='\33';

	int i = 1;
	int lenline;
	char c[2];

	lenline = strlen(ci);
	*co = '\000';

    if ( lenline == 0 ) return (true);
	c[0] = *(ci);

    while ((c[1] = *(ci+i++) ) != '\000') {
		switch (state) {

		case INITIAL:
		case SINGLECHAR:
			OutState = OUTPUT;
			if (c[0] == '\233' ) {
				state = SINGLECHAR;
				OutState = NOOUTPUT;
//				printf("<single char CSI>");
			}
			if (c[0] == ESC) {
				if ( c[1] == '[' ) {
					state = MULTICHAR1;
					OutState = NOOUTPUT;
//					printf("<multi char CSI>");
				} else if ( RANGE1(c[1]) ) {
					state = TWOCHAR;
					OutState = NOOUTPUT;
//					printf("<two char CSI>n");
				}
			} 
			break;

		case TWOCHAR:
			state = INITIAL;
			break;

		case MULTICHAR1:
			state = MULTICHAR2;
			break;

		case MULTICHAR2:
			if ( RANGE2(c[0]) ) {
				state = INITIAL;
//				printf("</multi char CSI>");
			}
			break;

		}
		
		switch (OutState) {
		
		case OUTPUT:
			*co = c[0];
			co++;
//			printf("%c", c[0] );
			break;
		case NOOUTPUT:
			break;

		}

		c[0] = c[1];
    }
	
	if (state == INITIAL) {
		*co = c[0];
		co++;
//		printf("%c", c[0] );
	}

	*co = '\000';
//	printf("\n");

	return (false);
}
