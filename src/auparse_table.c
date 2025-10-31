/*
 * auparse_table.c
 *
 *  Created on: Oct 15, 2025
 *      Author: dad
 */


#include "config.h"
#include "libaudit.h"
#include "common.h"
#include "auparse.h"
#include "ph-config.h"
#include <string.h>

// set WITH_APPARMOR so we will have access to all of the types defined in typetab.h
#ifdef WITH_APPARMOR
#define APPARMOR_SAVE	WITH_APPARMOR
#endif	// WITH_APPARMOR
#undef WITH_APPARMOR
#define WITH_APPARMOR

#undef _S
#define _S(id, str) {str,id},
// These are (hopefully) all of the valid field values
// Note that the number fields are not unique - they may point to the record type these fields are on??
const struct nv_list auparse_ids[] =
{
#include "typetab.h"
		{ WILDCARD, WILDCARDID },
		{ NULL, NOOPT }
};

// These are the allowable record types:
const struct nv_list auparse_types[] =
{
#include "msg_typetab.h"
		{ WILDCARD, WILDCARDID },
		{ NULL, NOOPT }
};
#undef _S

// reset WITH_APPARMOR to whatever it was set to before we messed with it
#undef WITH_APPARMOR
#ifdef APPARMOR_SAVE
#define WITH_APPARMOR APPARMOR_SAVE
#undef APPARMOR_SAVE
#endif	// APPARMOR_SAVE

int auparse_lookup_test (char ** mylabel) {
	int i = 0;

	int j = AUPARSE_TYPE_ESCAPED_KEY;
	while (auparse_ids[i].option != j) {
		if (auparse_ids[i].option == 0 ) break;
		i++;
	}
	*mylabel = auparse_ids[i].name;
	return i;
}
