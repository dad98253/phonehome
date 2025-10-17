/*
 * IsValidEmail.c
 *
 *  Created on: Oct 16, 2025
 *      Author: dad
 */

#include <regex.h>
#include <stdio.h>
#include <string.h>
#ifdef DEBUG
#include "debug2.h"
extern int WinFprintf(FILE *hf, const char * fmt,...);
#endif	// DEBUG

int IsValidEmail(const char *email) {
	regex_t regex;
	int reti;
	char msgbuf[100];

	// A simplified regex for basic email format validation
	// This regex is not exhaustive and may not cover all edge cases
	const char *pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";

	reti = regcomp(&regex, pattern, REG_EXTENDED);
	if (reti) {
#ifdef DEBUG
	if(debug) {
		WinFprintf(fp9, "Could not compile regex in IsValidEmail for %s \n",pattern);
	}
#endif	// DEBUG
		return 0;
	}

	reti = regexec(&regex, email, 0, NULL, 0);
	if (!reti) {
		regfree(&regex);
		return 1; // Valid
	} else if (reti == REG_NOMATCH) {
		regfree(&regex);
		return 0; // Invalid
	} else {
		regerror(reti, &regex, msgbuf, sizeof(msgbuf));
#ifdef DEBUG
		if(debug) {
			WinFprintf(fp9, "Regex match failed: %s\n", msgbuf);
		}
#endif	// DEBUG
		regfree(&regex);
		return 0;
	}
}



