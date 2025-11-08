/*
 ============================================================================
 Name        : ph-config.h
 Author      : dad
 Version     :
 Copyright   : 2025
 Description : The include file that goes with the ph-config.c routine.
               The based on the include file written by Steve Grubb for the
               audispd-pconfig.c configuration file management routine.
 ============================================================================
 */
/* based on audispd-pconfig.h by Steve Grubb --
 * modifications were made by John Kuras
 *
 * Steve's original code is:
 * Copyright 2007,2013,2023 Red Hat Inc.
 * All Rights Reserved.
 *
 * All modification or enhancements made by John Kuras are:
 * Copyright (c) John kuras 2025
 * All Rights Reserved.
 *
 * License for Steve's work states:
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * License for all modifications made by John Kuras is:
 * DWTFYWWI (Do whatever you want with it)
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   John Kuras <w7og@yahoo.com>
 */

#ifndef PH_CONFIG_H
#define PH_CONFIG_H


#ifndef PHCONFIGMAIN
#define EXTERN		extern
#define INITIZERO
#define INITSZERO
#define INITIONE
#define INITINEGONE
#define INITBOOLFALSE
#define INITBOOLTRUE
#define INITNULL
#define INITJKNULL
#define INITBUFFERSIZE
#define INITDIRSIZE
#define INITVERNAMELEN
#define INITNULLSTRING
#else  // PHCONFIGMAIN
#define EXTERN
#define INITIZERO	=0
#define INITSZERO	={0}
#define INITIONE	=1
#define INITINEGONE	=-1
#define INITBOOLFALSE	=false
#define INITBOOLTRUE	=true
#define INITNULL	=NULL
#define INITJKNULL  =JKNULL
#define INITBUFFERSIZE	=BUFFERSIZE
#define INITDIRSIZE		=DIRSIZE
#define INITVERNAMELEN  =VERNAMELEN
#define INITNULLSTRING  =""
#endif  // PHCONFIGMAIN

#include <sys/types.h>
#include "libaudit.h"
#define MAX_PLUGIN_ARGS 3
#define PASS	1
#define REJECT	0
#define MTA_DEFAULT	"localhost:25"
#define MAILTO_DEFAULT	"root"
#define SUBJECT_DEFAULT	"Warning from $hostname"
#define HASH_DEFAULT	1024
#define TYPE_HASH_DEFAULT	256
#define FIELD_HASH_DEFAULT	256
#define WILDCARD	"*"
#define WILDCARDID	-9998
#define NOOPT	-9999


typedef enum { DEFPASS, DEFREJECT } default_t;
typedef enum { FILPASS, FILREJECT, FILEND } filter_t;
typedef enum { FORMACRO, FORINCLUDE, FOREXCLUDE, FOREND } format_t;

typedef struct ph_config
{
	char *	name;	// config file basename
	char *	MTA;
	int		hashSize;
	unsigned long int hashmask;
	int		typehashSize;
	int		fieldhashSize;
	struct	ph_KeyConfig * phKeyConfig;		// a temporary pointer used during config input processing
	struct	ph_Type_Chain * TempTypeChain;	// a temporary pointer used during config input processing
	struct	ph_KeyConfig * statusKeyConfigHead;		// helpful link for cleanup
	struct	ph_Type_Chain * StatusTypeChainHead;	// helpful link for cleanup
	struct	ph_Chain * StatusFieldChainHead;		// helpful link for cleanup
	struct	ph_FilterChain * CurrentFilterChain;	// a temporary pointer used during config input processing
	int		phKeyConfigSize;
	char *	LastMailTo;
	char *	LastSubject;
	int		LastDefault;
} ph_config_t;

typedef struct ph_KeyConfig
{
	char *	key;
	char *	MailTo;
	char *	Subject;
	int		defaultPolicy;
	int		currentPolicy;
	int		currentFormat;
	struct	ph_FilterChain * phFilterChain;
	struct	ph_Chain * phFormatChain;
	struct	ph_Chain * phFormatMacroChain;
	struct	ph_KeyConfig * next;
	struct	ph_KeyConfig * statusKeyConfigNext;	// helpful link for cleanup
} ph_KeyConfig_t;

typedef struct ph_FilterChain
{
	char *	label;	// ??
	char *	value;	// ??
	int		PassOrReject;
	int		TypeHashSize;
	struct	ph_Type_Chain * DefaultTypeChain;	// (optional) if field filters are
												// defined prior to a record type
												// definition, they are saved here
	struct	ph_Type_Chain ** TypeHashArray;
	struct	ph_Type_Chain * AllTypeChainHead;	// points to a chain of all Record
												// Types included in this filter segment
	struct	ph_FilterChain * next;
} ph_FilterChain_t;

typedef struct ph_Type_Chain
{
	char *	Name;	// the user friendly name for the record type
	int		Type;	// the audit id number used for this type record
	int		Used;	// used during event filtering operation to prevent reuse of
					// type filters
					// must always be reset to zero when event evaluation is complete
	int		matches;	// used during event filtering operation to flag matched record type
						// must always be reset to zero when event evaluation is complete
	int		numOfFieldChildren;		// the total number of Field chain structs pointing to this parent
	int		lengthOfMaskArray;		// the length of the FieldMaskArray array
	unsigned long long int	*FieldMaskArray;	// used during event filtering operation
												// to keep track of matches to field
												// elements.
												// must always be reset to zero when
												// event evaluation is complete
	unsigned long long int	*MatchMaskArray;	// referenced during event filtering operation
												// to quicken match determination. Created
												// during config input processing
	int		PassOrReject;		// should be set to the appropriate value from the filter struct
	int		FieldHashSize;		// should be set to the appropriate value from the config struct
	struct	ph_Chain ** FieldHashArray;		// hash table used to find field elements
	struct	ph_Type_Chain * next;	// used to mitigate collisions in the type hash array
	struct	ph_Type_Chain * AllTypeChainNext;		// points to the next member
													// of the Type chain for this filter
	struct	ph_Type_Chain * StatusTypeChainNext;	// helpful link for cleanup
} ph_Type_Chain_t;

typedef struct ph_Chain
{
	char *	label;
	int		Type;
	char *	value;
	int		FieldID;
	int		PassOrReject;
	int		MatchMaskIndex;		// used in event evaluation to reference the appropriate
								// match mask back in the type struct
	unsigned long long int MatchMask;	// the mask used at the above index
	struct	ph_Type_Chain * ParentTypeRecord;	// used event evaluation to reference
												// the MatchMaskArray
	struct	ph_Chain * next;
	struct	ph_Chain * StatusFieldChainNext;	// helpful link for cleanup
} ph_Chain_t;

typedef struct nv_list
{
	char *	name;
	int		option;
} nv_list_t;

typedef struct nv_pair
{
	char *name;
	char *value;
	char *option;
	int name_len;
	int value_len;
	int option_len;
} nv_pair_t;

typedef struct kw_pair
{
	char *name;
	int (*parser)(struct nv_pair *, int, struct ph_config *);
	int max_options;
	int mask;
} kw_pair_t;

typedef enum {
    HEADER,
    KEY,
    DEFSET,
	FILTER,
	FORMAT
} modes;

EXTERN ph_KeyConfig_t ** phKeyConfigs INITNULL ;
EXTERN ph_Chain_t * phFormatChain INITNULL ;
EXTERN ph_Chain_t * phFormatMacroChain INITNULL;
EXTERN struct ph_config phConfig;



EXTERN void clear_phConfig(ph_config_t *phConfig);
EXTERN int  load_phConfig(ph_config_t *phConfig, char *file);
EXTERN void free_phConfig(ph_config_t *phConfig);

#undef EXTERN
#undef INITIZERO
#undef INITSZERO
#undef INITIONE
#undef INITINEGONE
#undef INITBOOLFALSE
#undef INITBOOLTRUE
#undef INITNULL
#undef INITJKNULL
#undef INITBUFFERSIZE
#undef INITDIRSIZE
#undef INITVERNAMELEN
#undef INITNULLSTRING

#endif	// PH_CONFIG_H

