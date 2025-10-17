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


#undef _S
#define _S(id, str) {str,id},

const struct nv_list auparse_ids[] =
{
#include "typetab.h"
		{ NULL, 0 }
};
#undef _S

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
