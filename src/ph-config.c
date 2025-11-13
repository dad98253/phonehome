/*
 ============================================================================
 Name        : ph-config.c
 Author      : dad
 Version     :
 Copyright   : 2025
 Description : manages the config file for the phonehome auditd plugin
 ============================================================================
 */
/* based on audispd-pconfig.c by Steve Grubb --
 * modifications were made by John Kuras
 *
 * Steve's original code is:
 * Copyright 2007,2010,2015,2021-23 Red Hat Inc.
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
 *
 */


#define _GNU_SOURCE // Required for fgets_unlocked
#include "config.h"


#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#define PHCONFIGMAIN
#include "ph-config.h"
#ifdef DEBUG
#include "debug2.h"
extern int WinFprintf(FILE *hf, const char * fmt,...);
#endif	// DEBUG
//#include "private.h"

#define IFNULL(ptr) ((ptr) == NULL ? "-null-" : (ptr))

extern int IsValidEmail(const char *email);

static char *get_line(FILE *f, char *buf, unsigned size, int *lineno, const char *file);
static int nv_split(char *buf, struct nv_pair *nv);
static struct kw_pair *kw_lookup(const char *val);
static int MTA_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int hash_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int key_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int To_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int Subject_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int default_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int filter_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int format_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int filter_rule_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int format_rule_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int sanity_check(ph_config_t *config, const char *file);
static char* valid_keywords( char **string );
static int nv_deesc(char *buf, char **name, int * name_len, char **ptr);
static void SetInputMode(modes newmode);
static int kw_unsetMask();
static int nv_lookup_name ( const nv_list_t *nv, char * myname );
char * nv_lookup_option ( const nv_list_t *nv, int myoption );
static ph_KeyConfig_t * TailofKeyConfig(ph_KeyConfig_t * phKeyConfigs);
static ph_Chain_t * find_chain_end(ph_Chain_t * chain);
static ph_FilterChain_t * find_filterchain_end(ph_FilterChain_t * chain);
static ph_Type_Chain_t * TailofTypeChain(ph_Type_Chain_t * phTypeChain);
static ph_Type_Chain_t * TailofAllTypeChain(ph_Type_Chain_t * phTypeChain);
static ph_Type_Chain_t * CreatFilterTypeChain (ph_FilterChain_t * TempFilterChain, int match, char * tempValue, ph_config_t *config);
ph_Chain_t * TailofFieldChain(ph_Chain_t * phFieldChain);
static ph_KeyConfig_t * TailofStatusKeyConfig(ph_KeyConfig_t * phKeyConfigs);
static ph_Type_Chain_t * TailofStatusTypeChain(ph_Type_Chain_t * phTypeChain);
static ph_Chain_t * TailofStatusFieldChain(ph_Chain_t * phFieldChain);
void free_chain(ph_Chain_t * chain);
void free_filterchain(ph_FilterChain_t * chain);
void freeStatusFieldChain(ph_Chain_t * chain);
void freeStatusTypeChain(ph_Type_Chain_t * chain);
void freeStatusKeyChain(ph_KeyConfig_t * chain);
void NukemAll ( ph_config_t *pphConfig );
static int WhitespaceSpan(char* str);
void DumpStructs ( char * configname, ph_config_t * Config, char * HashArrayName, ph_KeyConfig_t ** KeyHashArray );
void DumpKeyHashArray( char * t1, char * title, ph_KeyConfig_t ** KeyHashArray, int LenArray);
void DumpKeyConfigNext( char * t1, char * title, ph_KeyConfig_t * KeyConfig);
void DumpKeyConfig( char * t1, char * title, ph_KeyConfig_t * KeyConfig);
void DumpConfig( char * t1, char * title, ph_config_t * Config);
void DumpFilterChainNext( char * t1, char * title, ph_FilterChain_t * Config);
void DumpFilterChain( char * t1, char * title, ph_FilterChain_t * Config);
void DumpFormatChainNext( char * t1, char * title, ph_Chain_t * Config);
void DumpFormatChain( char * t1, char * title, ph_Chain_t * Config);
void DumpFormatMacroChainNext( char * t1, char * title, ph_Chain_t * Config);
void DumpFormatMacroChain( char * t1, char * title, ph_Chain_t * Config);
void DumpTypeChainNext( char * t1, char * title, ph_Type_Chain_t * Config);
void DumpTypeChain( char * t1, char * title, ph_Type_Chain_t * Config);
void DumpTypeChainHashArray( char * t1, char * title, ph_Type_Chain_t ** HashArray, int LenArray);
void DumpFieldChainNext( char * t1, char * title, ph_Chain_t * Config);
void DumpFieldChain( char * t1, char * title, ph_Chain_t * Config);
void DumpFieldChainHashArray( char * t1, char * title, ph_Chain_t ** HashArray, int LenArray);

extern const struct nv_list auparse_ids[];
extern const struct nv_list auparse_types[];

static struct kw_pair keywords[] =
{
  {"MTA",				MTA_parser,				0,	1 },
  {"hash",				hash_parser,			0,	1 },
  {"key",				key_parser,				0,	1 },
  {"To",				To_parser,				0,	1 },
  {"Subject",			Subject_parser,			0,	1 },
  {"default",			default_parser,			0,	1 },
  {"filter",			filter_parser,			0,	1 },
  {"format",			format_parser,			0,	1 },
  { NULL,				NULL,					0,	0 }
};

static const struct nv_list default_arg[] =
{
  {"pass",		DEFPASS },
  {"reject",	DEFREJECT },
  { NULL,		NOOPT }
};

static const struct nv_list filter_arg[] =
{
  {"pass",		FILPASS },
  {"reject",	FILREJECT },
  {"end",		FILEND },
  { NULL,		NOOPT }
};

static const struct nv_list format_arg[] =
{
  {"macro",		FORMACRO },
  {"include",	FORINCLUDE },
  {"exclude",	FOREXCLUDE },
  {"end",		FOREND },
  { NULL,		NOOPT }
};

/* The message mmode refers to where informational messages go
   0 - stderr, 1 - syslog, 2 - quiet. The default is quiet. */
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;
static const char * defaultMTA = MTA_DEFAULT ;
static const char * defaultMailTo = MAILTO_DEFAULT ;
static const char * defaultSubject = SUBJECT_DEFAULT ;
static modes mode = HEADER;
static int currentRecordType;	// used to identify default field filters (if == 0, use DefaultTypeChain)

void set_aumessage_mode(message_t mmode, debug_message_t debug)
{
        message_mode = mmode;
        debug_message = debug;
}

void audit_msg(int priority, const char *fmt, ...)
{
        va_list   ap;

        if (message_mode == MSG_QUIET)
                return;

        if (priority == LOG_DEBUG && debug_message == DBG_NO)
                return;

        va_start(ap, fmt);
        if (message_mode == MSG_SYSLOG)
                vsyslog(priority, fmt, ap);
        else {
                vfprintf(stderr, fmt, ap);
                fputc('\n', stderr);
        }
        va_end( ap );
}




/*
 * Set everything to its default value
*/
void clear_phConfig(ph_config_t * pphConfig)
{

	pphConfig->MTA = (char *)defaultMTA ;
	pphConfig->hashSize = HASH_DEFAULT;
	pphConfig->hashmask = HASH_DEFAULT - 1;
	pphConfig->typehashSize = TYPE_HASH_DEFAULT;
	pphConfig->fieldhashSize = FIELD_HASH_DEFAULT;
	pphConfig->phKeyConfig = NULL;
	pphConfig->phKeyConfigSize = 0;
	pphConfig->LastMailTo = (char *)defaultMailTo ;
	pphConfig->LastSubject = (char *)defaultSubject ;

	return;
}

int load_phConfig(struct ph_config *pphConfig, char *file)
{
	int fd;
	int rc;
	int lineno = 1;
	struct stat st;
	const struct kw_pair *kw;
	struct nv_pair nv;
	FILE *f;
	char buf[160];
	char *tmpString;

	syslog(LOG_INFO, "loading config file");

	clear_phConfig(pphConfig);

	/* open the file */
	rc = open(file, O_RDONLY);
	if (rc < 0) {
		if (errno != ENOENT) {
			audit_msg(LOG_ERR, "Error opening %s (%s)", file,
				strerror(errno));
			return 1;
		}
		audit_msg(LOG_WARNING,
			"Config file %s doesn't exist, skipping", file);
		return 0;
	}
	fd = rc;

	/* check the file's permissions: owned by root, not world writable,
	 * not symlink.
	 */
	if (fstat(fd, &st) < 0) {
		audit_msg(LOG_ERR, "Error fstat'ing config file (%s)",
			strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		audit_msg(LOG_ERR, "Error - %s isn't owned by root",
			file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		audit_msg(LOG_ERR, "Error - %s is world writable",
			file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		audit_msg(LOG_ERR, "Error - %s is not a regular file",
			file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		audit_msg(LOG_ERR, "Error - fdopen failed (%s)",
			strerror(errno));
		close(fd);
		return 1;
	}

	SetInputMode ( HEADER );
	while (get_line(f, buf, sizeof(buf), &lineno, file)) {
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "config line %i: " DBGBOLDYELLOW(%s) "\n",lineno, buf);
#endif	// DEBUG
		// convert line into name-value pair
		nv.name = NULL;
		nv.value = NULL;
		nv.option = NULL;
		rc = nv_split(buf, &nv);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "rc =  " DBGBOLDRED(%i) "\n",rc);
#endif	// DEBUG
		switch (rc) {
			case 0: // fine
				break;
			case 1: // not the right number of tokens.
				audit_msg(LOG_ERR,
				"Wrong number of arguments for line %d in %s",
					lineno, file);
				break;
			case 2: // no '=' sign
				audit_msg(LOG_ERR,
					"Missing equal sign for line %d in %s",
					lineno, file);
				break;
			case 3: // masked keyword
				audit_msg(LOG_ERR,
					"Out of order keyword for line %d in %s",
					lineno, file);
				audit_msg(LOG_ERR,
					"The permitted keywords in this context are: %s",
					valid_keywords(&tmpString));
					free(tmpString);
				break;
			case 4: // no matching "
				audit_msg(LOG_ERR,
					"No matching end quote for line %d in %s",
					lineno, file);
				break;
			default: // something else went wrong...
				audit_msg(LOG_ERR,
					"Unknown error for line %d in %s",
					lineno, file);
				break;
		}
		if (nv.name == NULL) {
			lineno++;
			continue;
		}
		if (nv.value == NULL) {
			fclose(f);
			return 1;
		}
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "nv.name, nv.value = " DBGBOLDRED(%s) "," DBGBOLDRED(%s) "\n",nv.name, nv.value);
#endif	// DEBUG

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			if ( mode != FILTER && mode != FORMAT ) {
				audit_msg(LOG_ERR,
					"Unknown keyword \"%s\" in line %d of %s",
					nv.name, lineno, file);
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "Unknown keyword \"" DBGBOLDRED(%s) "\" in line %d of %s\n", nv.name, lineno, file);
#endif	// DEBUG
				fclose(f);
				return 1;
			} else {	// in FILTER or FORMAT mode
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "Found potential auparse keyword \"" DBGBOLDRED(%s) "\" in line %d\n", nv.name, lineno);
#endif	// DEBUG
				//////////////////////////////// move this somewhere else?????
				// check for a match to auditd id names
#ifdef DEBUG
				int auid;
				if(debug) {
					if ( strcmp(nv.name,"type") == 0 ) {
	//					recid = nv_lookup_name ( auparse_types, nv.value );
						auid = -99;
					} else {
						auid = nv_lookup_name ( auparse_ids, nv.name );
					}
					WinFprintf(fp9, "auparse keyword \"" DBGBOLDRED(%s) "\"'s label id is " DBGBOLDGREEN(%i) " (decimal)\n", nv.name, auid);
				}
#endif	// DEBUG
				switch (mode) {
					case FILTER:
						rc = filter_rule_parser(&nv, lineno, pphConfig);
						break;
					case FORMAT:
						rc = format_rule_parser(&nv, lineno, pphConfig);
						break;
					default: // something went wrong...
						audit_msg(LOG_ERR,"Programming error at line %d in %s", __LINE__, __FILE__);
#ifdef DEBUG
						if(debug) WinFprintf(fp9, "Programming error at line %d in %s\n", __LINE__, __FILE__);
#endif	// DEBUG
						rc = -911;
						break;
				}
				if (rc != 0) {
					fclose(f);
					return 1; // local parser puts message out
				}
////////////////////////////////////////				xxxxxxxxxxxxx   process filters and formats here
				goto Nextline;
			}
		} else { // is this keyword masked?
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "kw->name, kw->mask = " DBGBOLDGREEN(%s) "," DBGBOLDGREEN(%i) "\n",kw->name, kw->mask);
#endif	// DEBUG
			if (kw->mask == 0) {
				if ( mode != FILTER && mode != FORMAT ) {
					audit_msg(LOG_ERR,
						"Out of order keyword \"%s\" in line %d of %s",
						nv.name, lineno, file);
#ifdef DEBUG
					if(debug) WinFprintf(fp9, "Out of order keyword \"%s\" in line %d of %s\n",
							nv.name, lineno, file);
#endif	// DEBUG
					fclose(f);
					return 1;
				}
			}
		}

		/* Check number of options */
		if (kw->max_options == 0 && nv.option != NULL) {
			audit_msg(LOG_ERR,
				"Keyword \"%s\" has invalid option "
				"\"%s\" in line %d of %s",
				nv.name, nv.option, lineno, file);
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "Keyword \"%s\" has invalid option "
					"\"%s\" in line %d of %s\n",
					nv.name, nv.option, lineno, file);
#endif	// DEBUG
			fclose(f);
			return 1;
		}

		/* dispatch to keyword's local parser */
		rc = kw->parser(&nv, lineno, pphConfig);
		if (rc != 0) {
			fclose(f);
			return 1; // local parser puts message out
		}
Nextline:	// if a filter or format definition statement was processed, the logic jumps here
		// free any strings in nv
		if ( nv.name != NULL ) free(nv.name);
		nv.name = NULL;
		if ( nv.value != NULL ) free(nv.value);
		nv.value = NULL;
		if ( nv.option != NULL ) free(nv.option);
		nv.option = NULL;
		lineno++;
	}

	fclose(f);
	pphConfig->name = strdup(basename(file));
	// reset the ph_config->phKeyConfig pointer to null (it is used as a temporary
	// pointer during config input processing
	pphConfig->phKeyConfig = NULL;
	// reset the ph_config->CurrentFilterChain temporary pointer
	pphConfig->CurrentFilterChain = NULL;
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDRED(**************************************  Config loaded  **************************************) "\n");
		if(debug) DumpStructs ( "phConfig", &phConfig, "phKeyConfigs", phKeyConfigs );
#endif	// DEBUG
	if (lineno > 1)
		return sanity_check(pphConfig, file);
	return 0;
}

static char *get_line(FILE *f, char *buf, unsigned size, int *lineno,
	 const char *file)
{
	int too_long = 0;

	while (fgets_unlocked(buf, size, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr) {
			if (!too_long) {
				*ptr = 0;
				return buf;
			}
			// Reset and start with the next line
			too_long = 0;
			*lineno = *lineno + 1;
		} else {
			// If a line is too long skip it.
			// Only output 1 warning
			if (!too_long)
				audit_msg(LOG_ERR,
					"Skipping line %d in %s: too long",
					*lineno, file);
			too_long = 1;
		}
	}
	return NULL;
}

static int nv_split(char *buf, struct nv_pair *nv)
{
	/* Get the name part */
	char *ptr;
	char * chdummy;
	int idummy;

	if ( buf == NULL ) return 5;
	if ( nv == NULL ) return 5;
	nv->name = NULL;
	nv->value = NULL;
	nv->option = NULL;
	nv->name_len = 0;
	nv->value_len = 0;
	nv->option_len = 0;

	if ( strlen(buf) == 0 ) return 0; // If there's nothing, go to next line
	if ( (WhitespaceSpan(buf)) == strlen(buf) ) return 0; // If it's a all blank line, go to next line
	if ( buf[0] == '#' ) return 0; // If there's a comment, go to next line

	int iret = nv_deesc(buf, &(nv->name), &(nv->name_len), &ptr);
	if ( iret == -1 ) return 4;

///////////////////////////////////////////////////////////////////
	// Check for a '=', if found, we will skip over it
	if ( *ptr == '=' ) ptr = memmove( ptr, ptr+1 , strlen(ptr+1) + 1 );


	/* get the value */
	iret = nv_deesc(ptr, &(nv->value), &(nv->value_len), &ptr);
	if ( iret == -1 ) return 4;


	/* See if there's an option */
	iret = nv_deesc(ptr, &(nv->option), &(nv->option_len), &ptr);
	if ( iret == -1 ) return 4;
	if ( iret == -2 ) return 0; // no option, that's ok


	/* Make sure there's nothing else */
	iret = nv_deesc(ptr, &chdummy, &idummy, &ptr);
	if ( iret > -1 ) return 1;

	/* Everything is OK */
	return 0;
}

static struct kw_pair *kw_lookup(const char *val)
{
	int i = 0;
	while (keywords[i].name != NULL) {
		if (strcasecmp(keywords[i].name, val) == 0)
			break;
		i++;
	}
	return &keywords[i];
}

static int MTA_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	int extra = 0;

    if (nv->value == NULL || nv->value_len == 0 ) {
    	audit_msg(LOG_ERR, "MTA value %s is missing - line %d", nv->value, line);
    	return 1;
    }
	// check for a port number separator
	if ( strpbrk(nv->value, ":") == NULL ) extra = 3;
	config->MTA = (char *)calloc(1, nv->value_len + 1 + extra);
	memmove( config->MTA, nv->value , nv->value_len );
    // check for a blank string

	if ( WhitespaceSpan(config->MTA) == strlen(config->MTA) ) {
    	audit_msg(LOG_ERR, "MTA value %s is blank - line %d", nv->value, line);
    	return 1;
    }
	if ( extra ) strcat(config->MTA, ":25"); // add default port 25 if none specified

	return 0;
}

static int hash_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char * str;
    char *endptr;
    long val;

    str = nv->value;
    // Handle empty string or string containing only whitespace
    if (str == NULL || *str == '\0') {
    	audit_msg(LOG_ERR, "hash value %s is missing - line %d", nv->value, line);
    	return 1;
    }

    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }

    // If after skipping whitespace, the string is empty, it's not an integer
    if (*str == '\0') {
    	audit_msg(LOG_ERR, "hash value %s is blank - line %d", nv->value, line);
    	return 1;
    }

    // Clear errno before calling strtol to reliably detect errors
    errno = 0;

    // Convert the string to a long integer
    val = strtol(str, &endptr, 10); // Base 10 for decimal integers

    // Check for conversion errors
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || // Overflow/underflow
        (errno != 0 && val == 0)) { // Other errors
    	audit_msg(LOG_ERR, "hash value %s is invalid - line %d", nv->value, line);
    	return 1;
    }

    // Check if the entire string was consumed by strtol (no non-numeric characters left)
    if (*endptr != '\0') {
    	audit_msg(LOG_ERR, "hash value %s Contains non-numeric characters after the number - line %d", nv->value, line);
    	return 1;
    }

	// save the integer value
	config->hashSize = (int)val;
	config->hashmask = (int)val - 1;

	return 0;
}

static int key_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	int i;
	unsigned long int result;
	unsigned long int sum = 0;
	ph_KeyConfig_t * tempKeyConfig;
	ph_KeyConfig_t * KeyConfigTail;

	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;

	SetInputMode(KEY);

	// check if the hash table has been initialized
	if ( phKeyConfigs == NULL ) {
		config->hashSize = config->hashSize - (config->hashSize)%256; // make sure its modulo 256
		if ( config->hashSize < 256 ) config->hashSize = 256;	// minimum hash table size
		// make sure the table size is a power of 2 and calculate the mask
		if ((config->hashSize & (config->hashSize - 1)) != 0) {
		    double log_result = log2((double)config->hashSize);
		    double ceil_result = ceil(log_result);
		    result = (unsigned int)pow(2.0, ceil_result);
		    if (( result & ( result - 1 ) ) != 0 ) {
		       	audit_msg(LOG_ERR, "hash mask calculation failed. hash,result = %i %u ... this is a program bug",config->hashSize,result);
		       	return 1;
		    }
		    config->hashSize = (int)result;
		}
		config->hashmask = config->hashSize - 1;
		phKeyConfigs = (ph_KeyConfig_t ** ) calloc(sizeof(ph_KeyConfig_t *), config->hashSize);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "Key hash table initialized; size is "DBGBOLDCYAN(%i) "\n",config->hashSize);
#endif	// DEBUG
	}

	// Allocate a new ph_KeyConfig struct and update the pointer in ph_config
	config->phKeyConfig = tempKeyConfig = (ph_KeyConfig_t *) calloc(sizeof(ph_KeyConfig_t), 1);
	tempKeyConfig->key = strndup(nv->value,nv->value_len);
	tempKeyConfig->MailTo = strdup(config->LastMailTo);
	tempKeyConfig->Subject = strdup(config->LastSubject);
	tempKeyConfig->defaultPolicy = -1;
	tempKeyConfig->currentPolicy = -1;
	tempKeyConfig->currentFormat = -1;
	// add the new key struct to the linked list for all key structs
	if ( config->statusKeyConfigHead == NULL ) {
		config->statusKeyConfigHead = tempKeyConfig;
	} else {
		TailofStatusKeyConfig(config->statusKeyConfigHead)->statusKeyConfigNext = tempKeyConfig;
	}
#ifdef DEBUG
	if(debug) WinFprintf(fp9, "new phKeyConfig struct created at "DBGBOLDCYAN(%p) " for " DBGBOLDGREEN(%s) "\n",tempKeyConfig, tempKeyConfig->key);
#endif	// DEBUG
	// hash the key
	for ( i = 0; i < strlen(nv->value); i++) {
		sum+= (unsigned char)( *((nv->value)+i) );
	}
	i = sum & config->hashmask;
	// Check for collision
	if ( phKeyConfigs[i] != NULL ) {
		// find the end of the linked list...
		KeyConfigTail = TailofKeyConfig(phKeyConfigs[i]);
		KeyConfigTail->next = tempKeyConfig;
	} else {
		phKeyConfigs[i] = tempKeyConfig;
	}
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDGREEN(%s) " hashed to " DBGBOLDYELLOW(%i) "\n",tempKeyConfig->key, i);
#endif	// DEBUG

	return 0;
}

static int To_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	// if value is blank, there's nothing to do
	if (nv->value == NULL) return 0;
	if ( nv->value_len == 0 ) return 0;

	SetInputMode(KEY);

	char * tempValue;
	tempValue = strdup(nv->value);

	if ( IsValidEmail(tempValue) == 0 ) {	// check the syntax of the email address
		audit_msg(LOG_WARNING, "The email address \"%s\" specified at line %d looks wrong, but it will be used anyway", tempValue, line);
	}

	// set the last used email in the config struct
	if ( config->LastMailTo != NULL && config->LastMailTo != defaultMailTo ) free(config->LastMailTo);
	config->LastMailTo = tempValue;

	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		if ( config->phKeyConfig->MailTo != NULL && config->phKeyConfig->MailTo != defaultMailTo ) free(config->phKeyConfig->MailTo);
		config->phKeyConfig->MailTo = strdup(tempValue);
	}

	return 0;

}

static int Subject_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char *result1;
	char *tempValue;

	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;

	SetInputMode(KEY);

	tempValue = strdup(nv->value);

	// check for the string "$hostname" if we find it, substitute our hostname
	if ( (result1 = strstr(tempValue, "$hostname")) != NULL ) {
		char hostname[HOST_NAME_MAX + 1]; // Buffer to store the hostname
		if (gethostname(hostname, HOST_NAME_MAX + 1) == 0) {
			char *temp2;
			temp2 = tempValue;
			tempValue = (char *) malloc(strlen(temp2) - strlen("$hostname") + strlen(hostname) + 2 );
			int numtocpy = (int)(result1-temp2);
			strncpy(tempValue, temp2, numtocpy );
			*(tempValue+numtocpy) = '\000';
			strcat(tempValue, hostname);
			char * start = ( result1 + strlen("$hostname") );
			strcat(tempValue, start);
			free(temp2);
		} else {
			audit_msg(LOG_WARNING, "Error getting hostname at line %i because %s", line, strerror(errno));
		}
	}

	// set the last used subject in the config struct
	if ( config->LastSubject != NULL && config->LastSubject != defaultSubject ) free(config->LastSubject);
	config->LastSubject = tempValue;

	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		if ( config->phKeyConfig->Subject != NULL && config->phKeyConfig->Subject != defaultSubject ) free(config->phKeyConfig->Subject);
		config->phKeyConfig->Subject = strdup(tempValue);
	}

	return 0;
}

static int default_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char *tempValue;

	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;

	SetInputMode(KEY);

	tempValue = strdup(nv->value);
	// check for an option match
	int match = nv_lookup_name ( default_arg, tempValue );

	if ( match == NOOPT ) {
		audit_msg(LOG_ERR, "\"%s\" not a valid default option - line %d", tempValue, line);
		return 0;
	}
	free(tempValue);

	// set the last used default in the config struct
	config->LastDefault = match;

	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		config->phKeyConfig->defaultPolicy = match;
	}

	return 0;
}

static int filter_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char *tempValue;
	ph_FilterChain_t * TempFilterChain;

	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;
	if ( nv->name == NULL ) return 0;
	if ( nv->name_len == 0 ) return 0;

	SetInputMode(FILTER);

	tempValue = strdup(nv->value);
	// check for an option match
	int match = nv_lookup_name ( filter_arg, tempValue );
	if ( match == NOOPT ) {
		audit_msg(LOG_ERR, "\"%s\" not a valid filter option - line %d", tempValue, line);
		free(tempValue);
		return 0;
	}

	// no filterchain, yet. create one
	if ( config->phKeyConfig->phFilterChain == NULL ) {
		TempFilterChain = config->phKeyConfig->phFilterChain = (ph_FilterChain_t *) calloc(sizeof(ph_FilterChain_t), 1);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "new filter chain struct created at "DBGBOLDCYAN(%p) "\n",TempFilterChain);
#endif	// DEBUG
	} else {
		TempFilterChain = find_filterchain_end(config->phKeyConfig->phFilterChain);
		TempFilterChain->next = (ph_FilterChain_t *) calloc(sizeof(ph_FilterChain_t), 1);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "new filter chain struct created at " DBGBOLDCYAN(%p) " added at the end of the chain following " DBGBOLDCYAN(%p) "\n",TempFilterChain->next ,TempFilterChain);
#endif	// DEBUG
		TempFilterChain = TempFilterChain->next;
	}
	TempFilterChain->TypeHashSize = config->typehashSize;
	TempFilterChain->label = strndup(nv->name,nv->name_len);
	TempFilterChain->value = tempValue;
	TempFilterChain->PassOrReject = match;
	currentRecordType = 0;	// reset the record type to none


	if ( match == FILEND ) {
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDCYAN(FILTER END detected) "\n");
#endif	// DEBUG
		// tack wild card pass/reject at the end of the list to iplement the default feature
		TempFilterChain->next = (ph_FilterChain_t *) calloc(sizeof(ph_FilterChain_t), 1);
		TempFilterChain = TempFilterChain->next;
		TempFilterChain->PassOrReject = config->phKeyConfig->defaultPolicy;
		TempFilterChain->label = strdup("*");
		TempFilterChain->value = strdup("*");
		// reset input mode
		SetInputMode(KEY);
		return 0;
	}
	// must be a pass or reject command: set TempFilterChain
	TempFilterChain->PassOrReject = match;
	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		config->phKeyConfig->currentPolicy = match;
	} else {
		audit_msg(LOG_ERR, "Out of order filter option; must define key before filter - line %d", line);
		return 1;
	}

	return 0;
}

static int format_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char *tempValue;
	ph_Chain_t * TempFormatChain;
#ifdef DEBUG
	if(debug) WinFprintf(fp9, "In format_parser at line %d in %s\n", __LINE__, __FILE__);
#endif	// DEBUG
	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;

	SetInputMode(FORMAT);

	tempValue = strdup(nv->value);
	// check for an option match
	int match = nv_lookup_name ( format_arg, tempValue );

	if ( match == NOOPT ) {
		audit_msg(LOG_ERR, "\"%s\" not a valid format option - line %d", tempValue, line);
		return 0;
	}
	free(tempValue);

/*	if ( match == FOREND ) {
		// tack wild card pass/reject at the end of the list to iplement the default feature
		if ( config->phKeyConfig->phFormatChain == NULL ) {
			// no chain, yet. create one and set the wild card
			TempFormatChain = config->phKeyConfig->phFormatChain = (ph_Chain_t *) calloc(sizeof(ph_Chain_t), 1);
		} else {
			// find the end of the chain
			TempFormatChain = find_chain_end(config->phKeyConfig->phFormatChain);
			TempFormatChain->next = (ph_Chain_t *) calloc(sizeof(ph_Chain_t), 1);
			TempFormatChain = TempFormatChain->next;
		}
		if ( config->phKeyConfig->currentFormat == FORINCLUDE ) {
			TempFormatChain->PassOrReject = FOREXCLUDE;
		} else {
			TempFormatChain->PassOrReject = FORINCLUDE;
		}
		TempFormatChain->label = strdup("*");
		TempFormatChain->value = strdup("*");
		// reset input mode
		SetInputMode(KEY);
		return 0;
	}
	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		config->phKeyConfig->currentFormat = match;
	} else {
		audit_msg(LOG_ERR, "Out of order filter option; must define key before filter - line %d", line);
		return 1;
	}
*/
	return 0;
}

static int filter_rule_parser(struct nv_pair *nv, int line, ph_config_t *config) {
	char *tempValue;
	int match;
	int auid;
	int i;
	long long int sum = 0;
	ph_FilterChain_t * TempFilterChain;
	ph_Type_Chain_t * TempTypeChain;
	ph_Chain_t * TempFieldChain;
	ph_Chain_t * FieldChainTail;

	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;
	tempValue = strdup(nv->value);

	if ( config->phKeyConfig->phFilterChain == NULL ) {
		audit_msg(LOG_ERR, "\"%s %s\" at line %d appears to be out of order - expecting a \"filter\" directive", nv->name, tempValue, line);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "\"%s %s\" at line %d appears to be out of order - expecting a \"filter\" directive", nv->name, tempValue, line);
#endif	// DEBUG
		free(tempValue);
		return 0;
	}
	// find the last thing we worked on...
	TempTypeChain = config->TempTypeChain;
	// find the current filter chain tail
	TempFilterChain = find_filterchain_end(config->phKeyConfig->phFilterChain);
	// check for an record type match
	if ( strcmp(nv->name,"type") == 0 ) {
		match  = nv_lookup_name ( auparse_types, tempValue );
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDGREEN(match %s) " found - record type is " DBGBOLDRED(%i) "\n", tempValue, match);
#endif	// DEBUG
		if ( match == NOOPT ) {
			audit_msg(LOG_ERR, "\"%s\" not a valid audit record type - line %d", tempValue, line);
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "\"%s\" not a valid audit record type - line %d\n", tempValue, line);
#endif	// DEBUG
			free(tempValue);
			return 0;
		}
		currentRecordType = 1;	// a record type is found. Any field filters that follow apply to this record
		// create a type filter table entry
		TempTypeChain = CreatFilterTypeChain (TempFilterChain, match, tempValue, config);
		config->TempTypeChain = TempTypeChain;
		// make sure that the filterchain
	} else {
		// check if we have encountered a type card, yet
		if ( currentRecordType == 0 ) {
			// this appears to be a field match request, but the user didn't say which record type to expect it on
			// we will save this in the DefaultTypeChain of the current filter chain...
			// check to see if the struct has been allocated
			if ( TempFilterChain->DefaultTypeChain == NULL ){
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "no type card prior to field filters, create a " DBGBOLDRED(DefaultTypeChain) "\n");
#endif	// DEBUG
				TempFilterChain->DefaultTypeChain = CreatFilterTypeChain (TempFilterChain, NOOPT, strdup("-nil-"), config);
			}
			TempTypeChain = TempFilterChain->DefaultTypeChain;
			config->TempTypeChain = TempTypeChain;
			currentRecordType = 2;
		}
		// must be a non-type field match request
		// check the name to see if it makes sense
		if ( ( auid = nv_lookup_name ( auparse_ids, nv->name ) ) == NOOPT ) {
			audit_msg(LOG_ERR, "Warning: \"%s\" at line %d is an unknown audit field - we will try to match it anyway", nv->name , line);
		}
		// check for the special case of "* *" - this wildcard combination should match anything and does not require a record type
		if ( auid == WILDCARDID && ( strcmp(tempValue,"*") == 0 ) ) {
#ifdef DEBUG
			if(debug) WinFprintf(fp9, DBGBOLDRED(wild card %s:%s detected) "\n", nv->name, tempValue);
#endif	// DEBUG
//			if ( TempFilterChain->DefaultTypeChain == NULL ) {
//				TempFilterChain->DefaultTypeChain = CreatFilterTypeChain (TempFilterChain, auid, tempValue, config);
//			}
		}
		// if there is no DefaultTypeChain defined, what record do we apply it to?
//		if ( TempFilterChain->DefaultTypeChain == NULL ) {
//			audit_msg(LOG_ERR, "\"%s %s\" at line %d appears to be defining a field match without first specifying a recored type - it will be ignored", nv->name , tempValue, line);
//			free(tempValue);
//			return 0;
//		}
		// create a field hash table if one does not exist
		if ( TempTypeChain->FieldHashArray == NULL ) {
#ifdef DEBUG
			if(debug) WinFprintf(fp9, DBGBOLDRED(FieldHashArray) " created\n");
#endif	// DEBUG
			TempTypeChain->FieldHashArray = (ph_Chain_t **) calloc(sizeof(ph_Chain_t *), config->fieldhashSize);
		}
		// Allocate a new ph_Chain struct
		TempFieldChain = (ph_Chain_t *) calloc(sizeof(ph_Chain_t), 1);
		TempFieldChain->label = strdup(nv->name);
		TempFieldChain->Type = auid;
		TempFieldChain->value = tempValue;
		TempFieldChain->ParentTypeRecord = TempTypeChain; // link to the parent type record
		// add the new field struct to the linked list for all field structs
		if ( config->StatusFieldChainHead == NULL ) {
			config->StatusFieldChainHead = TempFieldChain;
		} else {
			TailofStatusFieldChain(config->StatusFieldChainHead)->StatusFieldChainNext = TempFieldChain;
		}
		// re-calculate the field mask for the parent type struct to include our new field struct
		// get the total number of fields under the parent type struct - this is the mask bit index for our field
		int FieldSeqNum = TempTypeChain->numOfFieldChildren;
		(TempTypeChain->numOfFieldChildren)++;	// increment the field count in the parent type struct
		TempFieldChain->MatchMask = 1ull << ( FieldSeqNum % 64 );
		TempFieldChain->MatchMaskIndex = FieldSeqNum / 64;
		// make sure the parent's MaskArray is big enough
		if ( TempTypeChain->MatchMaskArray == NULL ) {
			// no MaskArray, make it length 1
			TempTypeChain->MatchMaskArray = (unsigned long long int	*) calloc(sizeof(unsigned long long int), 1);
			TempTypeChain->FieldMaskArray = (unsigned long long int	*) calloc(sizeof(unsigned long long int), 1);
			TempTypeChain->lengthOfMaskArray = 1;
		}
		if ( TempTypeChain->lengthOfMaskArray < (TempFieldChain->MatchMaskIndex + 1) ) {
			// we need to make the MaskArray bigger
			unsigned long long int	* OldMaskArray = TempTypeChain->MatchMaskArray;
			TempTypeChain->MatchMaskArray = (unsigned long long int	*) calloc(sizeof(unsigned long long int), TempFieldChain->MatchMaskIndex + 1);
			for (i=0; i<TempTypeChain->lengthOfMaskArray; i++) {
				TempTypeChain->MatchMaskArray[i] = OldMaskArray[i];
			}
			free(OldMaskArray);
			free(TempTypeChain->FieldMaskArray); // FieldMaskArray should always be all zeros - just free it & make new one
			TempTypeChain->FieldMaskArray = (unsigned long long int	*) calloc(sizeof(unsigned long long int), TempFieldChain->MatchMaskIndex + 1);
		}
		// or our new MatchMask into the parent's MatchMaskArray
		(TempTypeChain->MatchMaskArray[TempFieldChain->MatchMaskIndex]) = TempTypeChain->MatchMaskArray[TempFieldChain->MatchMaskIndex] | TempFieldChain->MatchMask;
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "field filter " DBGBOLDRED(%s=%s) " created, auid = " DBGBOLDGREEN(%i)  "\n", TempFieldChain->label, TempFieldChain->value, TempFieldChain->Type);
#endif	// DEBUG
		// hash the label
		for ( i = 0; i < strlen(nv->name); i++) {
			sum+= (unsigned char)( *((nv->name)+i) );
		}
		i = sum % TempTypeChain->FieldHashSize;
		// Check for collision
		if ( TempTypeChain->FieldHashArray[i] != NULL ) {
			// find the end of the linked list...
			FieldChainTail = TailofFieldChain(TempTypeChain->FieldHashArray[i]);
			FieldChainTail->next = TempFieldChain;
		} else {
			TempTypeChain->FieldHashArray[i] = TempFieldChain;
		}
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "field hash is " DBGBOLDGREEN(%i) " created table entry at " DBGBOLDGREEN(%p)  "\n", i, &(TempTypeChain->FieldHashArray[i]) );
#endif	// DEBUG
	}

	return 0;
}

ph_Type_Chain_t * CreatFilterTypeChain (ph_FilterChain_t * TempFilterChain, int match, char * tempValue, ph_config_t *config) {
	ph_Type_Chain_t * TempTypeChain;
	ph_Type_Chain_t * TypeChainTail;
	int i;

	if ( TempFilterChain->TypeHashArray == NULL ) {
		TempFilterChain->TypeHashArray = (ph_Type_Chain_t **) calloc(sizeof(ph_Type_Chain_t *), TempFilterChain->TypeHashSize);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "TypeHashArray created at " DBGBOLDCYAN(%p) " with length " DBGBOLDGREEN(%i) " for the " DBGBOLDRED(%s) " filter struct at " DBGBOLDCYAN(%p) "\n",
				TempFilterChain->TypeHashArray, TempFilterChain->TypeHashSize, TempFilterChain->value, TempFilterChain);
#endif	// DEBUG
	}

	// Allocate a new ph_Type_Chain struct
	TempTypeChain = (ph_Type_Chain_t *) calloc(sizeof(ph_Type_Chain_t), 1);
	TempTypeChain->Name = tempValue;
	TempTypeChain->Type = match;
	TempTypeChain->FieldHashSize = config->fieldhashSize;
	// add the new type struct to the linked list for this filter
	if ( TempFilterChain->AllTypeChainHead == NULL ) {
		TempFilterChain->AllTypeChainHead = TempTypeChain;
	} else {
		TailofAllTypeChain(TempFilterChain->AllTypeChainHead)->AllTypeChainNext = TempTypeChain;
	}
	// add the new type struct to the linked list for all type structs
	if ( config->StatusTypeChainHead == NULL ) {
		config->StatusTypeChainHead = TempTypeChain;
	} else {
		TailofStatusTypeChain(config->StatusTypeChainHead)->StatusTypeChainNext = TempTypeChain;
	}
#ifdef DEBUG
	if(debug) WinFprintf(fp9, "new TypeChain struct created at " DBGBOLDCYAN(%p) " for " DBGBOLDGREEN(%s) "\n",TempTypeChain, tempValue);
#endif	// DEBUG
	if ( match == NOOPT ) return (TempTypeChain);
	// hash the key
	i = match % TempFilterChain->TypeHashSize;
#ifdef DEBUG
	if ( TempFilterChain->TypeHashArray == NULL ) {
		if (debug) WinFprintf(fp9, DBGBOLDRED(TempFilterChain->TypeHashArray == NULL) " at line %d in %s\n", __LINE__, __FILE__);
		audit_msg(LOG_ERR,"phonehome audit plugin is exiting due to program bug at line %d in %s", __LINE__, __FILE__);
	}
#endif	// DEBUG
	// Check for collision
	if ( TempFilterChain->TypeHashArray[i] != NULL ) {
		// find the end of the linked list...
		TypeChainTail = TailofTypeChain(TempFilterChain->TypeHashArray[i]);
		TypeChainTail->next = TempTypeChain;
	} else {
		TempFilterChain->TypeHashArray[i] = TempTypeChain;
	}
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDGREEN(%s) " hashed to " DBGBOLDGREEN(%i) " ie, hash table entry = " DBGBOLDCYAN(%p) "\n",tempValue, i, &(TempFilterChain->TypeHashArray[i]) );
#endif	// DEBUG
	return (TempTypeChain);
}


static int format_rule_parser(struct nv_pair *nv, int line, ph_config_t *config) {
#ifdef DEBUG
	if(debug) WinFprintf(fp9, "In format_rule_parser at line %d in %s\n", __LINE__, __FILE__);
#endif	// DEBUG
	return 0;
}
/*
 * This function is where we do the integrated check of the audispd config
 * options. At this point, all fields have been read. Returns 0 if no
 * problems and 1 if problems detected.
 */
static int sanity_check(ph_config_t *config, const char *file)
{
	/* Error checking */
/*	if (config->active == A_YES) {
		struct stat buf;

		if (config->path == NULL) {
			audit_msg(LOG_ERR,
		    "Error - plugin (%s) is active but no path given", file);
			return 1;
		}
		// Don't check builtins
		if (strncasecmp(config->path, "builtin_", 8) == 0)
			goto out;

		// If the file exists, see that its regular, owned by root,
		// and not world anything
		if (stat(config->path, &buf) < 0) {
			audit_msg(LOG_ERR, "Unable to stat %s (%s)",
				  config->path,	strerror(errno));
			return 1;
		}
		if (!S_ISREG(buf.st_mode)) {
			audit_msg(LOG_ERR, "%s is not a regular file",
				 config->path);
			return 1;
		}
		if (buf.st_uid != 0) {
			audit_msg(LOG_ERR, "%s is not owned by root",
				 config->path);
			return 1;
		}
		if ((buf.st_mode & (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP)) !=
				   (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP)) {
			audit_msg(LOG_ERR, "%s permissions should be 0750",
				 config->path);
			return 1;
		}
		// Passes, record inode
		config->inode = buf.st_ino;
	}
out:
*/
	return 0;
}


void free_chain(ph_Chain_t * chain) {

	if ( chain == NULL ) return;
	if ( chain->next != NULL ) free_chain( chain->next );

	free( chain->label );
	free( chain->value );
	free ( chain );
	chain = NULL;

	return;
}

void free_filterchain(ph_FilterChain_t * chain) {

	if ( chain == NULL ) return;
	if ( chain->next != NULL ) free_filterchain( chain->next );


	if ( chain->label != NULL ) free( chain->label );
	chain->label = NULL;
	if ( chain->value != NULL ) free( chain->value );
	chain->value = NULL;
	if ( chain->TypeHashArray != NULL ) free( chain->TypeHashArray );
	chain->TypeHashArray = NULL;
	// if ( chain->DefaultTypeChain != NULL ) xxx ?? - should be caught by statusTypeChain
	free ( chain );
	chain = NULL;

	return;
}


ph_Chain_t * find_chain_end(ph_Chain_t * chain) {

	if ( chain->next == NULL ) {
		return (chain);
	} else {
		return (find_chain_end( chain->next ));
	}

}


ph_FilterChain_t * find_filterchain_end(ph_FilterChain_t * chain) {

	if ( chain->next == NULL ) {
		return (chain);
	} else {
		return (find_filterchain_end( chain->next ));
	}

}

void free_phKeyConfig(ph_KeyConfig_t * phKeyConfig) {

	if ( phKeyConfig->next == NULL ) {
		return;
	} else {
		free_phKeyConfig( phKeyConfig->next );
	}
	free( phKeyConfig->MailTo );
	free( phKeyConfig->Subject );
	free_filterchain( phKeyConfig->phFilterChain );
	free_chain( phKeyConfig->phFormatChain );
	free_chain( phKeyConfig->phFormatMacroChain );
	free ( phKeyConfig );
	phKeyConfig = NULL;

	return;
}

void NukemAll ( ph_config_t *pphConfig ) {
	free_phConfig(pphConfig);
	if ( phKeyConfigs != NULL ) free ( phKeyConfigs );
	phKeyConfigs = NULL;
}

void free_phConfig(ph_config_t *pphConfig)
{
	if (pphConfig == NULL) return;
	//if ( pphConfig->phKeyConfig != NULL ) free_phKeyConfig( pphConfig->phKeyConfig ); // free hash table
	pphConfig->hashSize = 0;
	pphConfig->hashmask = 0;
	pphConfig->typehashSize = 0;
	pphConfig->fieldhashSize = 0;
	pphConfig->LastDefault = 0;
	pphConfig->phKeyConfigSize = 0;
	freeStatusFieldChain(pphConfig->StatusFieldChainHead);
	pphConfig->StatusFieldChainHead = NULL;
	freeStatusTypeChain(pphConfig->StatusTypeChainHead);
	pphConfig->StatusTypeChainHead = NULL;
	freeStatusKeyChain(pphConfig->statusKeyConfigHead);
	pphConfig->statusKeyConfigHead = NULL;
	if ( pphConfig->name != NULL ) free(pphConfig->name);
	pphConfig->name = NULL;
	if ( pphConfig->MTA != NULL ) free(pphConfig->MTA);
	pphConfig->MTA = NULL;
	if ( pphConfig->LastMailTo != NULL ) free(pphConfig->LastMailTo);
	pphConfig->LastMailTo = NULL;
	if ( pphConfig->LastSubject != NULL ) free(pphConfig->LastSubject);
	pphConfig->LastSubject = NULL;

	return;
}

void freeStatusFieldChain(ph_Chain_t * chain) {

	if ( chain == NULL ) return;
	if ( chain->StatusFieldChainNext != NULL ) freeStatusFieldChain( chain->StatusFieldChainNext );

	if ( chain->label != NULL ) free( chain->label );
	chain->label = NULL;
	if ( chain->value != NULL ) free( chain->value );
	chain->value = NULL;
	free ( chain );
	chain = NULL;

	return;
}

void freeStatusTypeChain(ph_Type_Chain_t * chain) {

	if ( chain == NULL ) return;
	if ( chain->StatusTypeChainNext != NULL ) freeStatusTypeChain( chain->StatusTypeChainNext );

	if ( chain->Name != NULL ) free( chain->Name );
	chain->Name = NULL;
	if ( chain->FieldMaskArray != NULL ) free( chain->FieldMaskArray );
	chain->FieldMaskArray = NULL;
	if ( chain->MatchMaskArray != NULL ) free( chain->MatchMaskArray );
	chain->MatchMaskArray = NULL;
	if ( chain->FieldHashArray != NULL ) free( chain->FieldHashArray );
	chain->FieldHashArray = NULL;
	free ( chain );
	chain = NULL;

	return;
}

void freeStatusKeyChain(ph_KeyConfig_t * chain) {

	if ( chain == NULL ) return;
	if ( chain->statusKeyConfigNext != NULL ) freeStatusKeyChain( chain->statusKeyConfigNext );

	if ( chain->key != NULL ) free( chain->key );
	chain->key = NULL;
	if ( chain->MailTo != NULL ) free( chain->MailTo );
	chain->MailTo = NULL;
	if ( chain->Subject != NULL ) free( chain->Subject );
	chain->Subject = NULL;
	free_filterchain(chain->phFilterChain);
	chain->phFilterChain = NULL;

	free ( chain );
	chain = NULL;

	return;
}


static char* valid_keywords( char **string ) {
	*string = (char *)malloc(2);
	**string = '\000';
	return (*string);
}

int WhitespaceSpan(char* str) {
	int iret = 0;
    if (str == NULL) {
        return 0;
    }
    while (*str != '\0' && isspace((unsigned char)*str)) {
        str++;
        iret++;
    }
    return iret;
}


static int nv_deesc(char *buf, char **name, int * name_len, char **ptr) {
// this function identifies strings enclosed in double quotes as well as escaped characters
// since all escaped characters start with a "\" (backslash), it is simply removed and the
// scan starts again after the next character.
// it then looks for either a whitespace (indicating a field delimiter) or end of string
// a side effect of this process is that tabs contained within a quoted string will be
// "de-escaped" and returned as a "t".
//
// buf:			the input buffer - it will not be changed
// name:		the next label field found - a new string will be allocated - ends up in nv.
// name_len:	the length of the above string - ends up in nv.
// ptr:			the pointer to the next (unprocessed) character in buf when we are done
// returns the value of name_len on success, various negative values on errors

	int fldlen = 0;
	char * strStart;
	char * tmptr;
	int isizews;
	int lensubstr;

	if ( (isizews = WhitespaceSpan(buf)) == strlen(buf) ) {
		// all whitespace - zero len buf .. should be impossible
		*buf = '\000';
	} else {
		if ( isizews ) {
			// move non white to front of string
			lensubstr = strlen(buf+isizews);
			memmove(buf, buf+isizews, lensubstr );
			*(buf+lensubstr) = '\000';
		}
	}
	*ptr = buf;
	if ( **ptr == '\000' ) return -2;

	/*
	if first char is a *, skip over it and...
	look for either a \ or "
	if the " comes next it is oes (done)
	if the \ comes next copy over it, skip over the first letter copied & continue search
	if neither found, no matching " !

	if first char is not a *...
	look for either a \ or " "
	if a " " is found or neither is found, it is eos (done)
	if the \ comes next copy over it, skip over the first letter copied & continue search
*/
	if ( **ptr == '"' ) {
		// first character is a double quote, find the matching double quote
		(*ptr)++;
		strStart = *ptr;
		while(1) {
			if ( (tmptr = strpbrk(*ptr, "\\\"")) == NULL ) return -1;
			if ( *tmptr == '\"' ) { // matching " found
				fldlen = (int)(tmptr - strStart );
				memmove( tmptr, tmptr+1 , strlen(tmptr+1) + 1 ); // remove the closing " in case we are not done
				break;
			}
			*ptr = memmove( tmptr, tmptr+1 , strlen(tmptr+1) + 1 ); // found a \ .. un-escape it
		}
	} else {
		// not a quoted string... de-escape it and find the next blank
		strStart = *ptr;
		while(1) {
			if ( (tmptr = strpbrk(*ptr, "\\ \t")) == NULL ) { // end of string found
				fldlen = strlen(*ptr);
				break;
			}
			if ( *tmptr == ' ' || *tmptr == '\t') { // blank space found
				fldlen = (int)(tmptr - strStart );
				break;
			}
			*ptr = memmove( tmptr, tmptr+1 , strlen(tmptr+1) + 1 ); // found a \ .. un-escape it
		}
	}

	if (fldlen) {
		*name = (char*)malloc(fldlen+1);	// allocate a string for name (ends up in nv.name)
		strncpy(*name,strStart,fldlen);
		*(*name+fldlen) = '\000';
	} else {
		*name = (char*)malloc(1);	// allocate a zero length string for name
		*(*name) = '\000';
	}
	*name_len = fldlen;
	*ptr = (*ptr)+=fldlen;
	*ptr = *ptr+WhitespaceSpan(*ptr);
	return fldlen;
}

static int kw_unsetMask() {
	int i = 0;
	while (keywords[i].name != NULL) {
		keywords[i].mask = 1;
		i++;
	}
	return 1;
}

void SetInputMode(modes newmode) {
	struct kw_pair *kw;

	mode = newmode;
	kw_unsetMask();

	switch (mode) {
	    case HEADER:
	        break;
	    case KEY:
	    	kw = kw_lookup("MTA");
	    	kw->mask = 0;
	    	kw = kw_lookup("hash");
	    	kw->mask = 0;
	        break;
	    case DEFSET:
	    	kw = kw_lookup("MTA");
	    	kw->mask = 0;
	    	kw = kw_lookup("hash");
	    	kw->mask = 0;
	    	kw = kw_lookup("default");
	    	kw->mask = 0;
	        break;
	    case FILTER:
	    	kw = kw_lookup("MTA");
	    	kw->mask = 0;
	    	kw = kw_lookup("hash");
	    	kw->mask = 0;
	    	kw = kw_lookup("key");
	    	kw->mask = 0;
	    	kw = kw_lookup("To");
	    	kw->mask = 0;
	    	kw = kw_lookup("Subject");
	    	kw->mask = 0;
	    	kw = kw_lookup("default");
	    	kw->mask = 0;
	    	kw = kw_lookup("format");
	    	kw->mask = 0;
	        break;
	    case FORMAT:
	    	kw = kw_lookup("MTA");
	    	kw->mask = 0;
	    	kw = kw_lookup("hash");
	    	kw->mask = 0;
	    	kw = kw_lookup("key");
	    	kw->mask = 0;
	    	kw = kw_lookup("To");
	    	kw->mask = 0;
	    	kw = kw_lookup("Subject");
	    	kw->mask = 0;
	    	kw = kw_lookup("default");
	    	kw->mask = 0;
	    	kw = kw_lookup("filter");
	    	kw->mask = 0;
	        break;
	    default:
			audit_msg(LOG_ERR, "SetInputMode called with unknown mode %i ",mode);
	}


	return;
}

int nv_lookup_name ( const nv_list_t *nv, char * myname ) {
	int i = 0;

	while (nv[i].name != NULL) {
		if (strcasecmp(myname, nv[i].name) == 0) return (nv[i].option);
		i++;
	}

	return (NOOPT);
}

char * nv_lookup_option ( const nv_list_t *nv, int myoption ) {
	int i = 0;

	while ( nv[i].name != NULL) {
		if (nv[i].option == myoption ) break;
		i++;
	}

	return (nv[i].name);
}

ph_KeyConfig_t * TailofKeyConfig(ph_KeyConfig_t * phKeyConfigs) {

		if ( phKeyConfigs->next == NULL ) {
			return (phKeyConfigs);
		} else {
			return ( TailofKeyConfig( phKeyConfigs->next ) );
		}
}

ph_KeyConfig_t * TailofStatusKeyConfig(ph_KeyConfig_t * phKeyConfigs) {

		if ( phKeyConfigs->statusKeyConfigNext == NULL ) {
			return (phKeyConfigs);
		} else {
			return ( TailofStatusKeyConfig( phKeyConfigs->statusKeyConfigNext ) );
		}
}

ph_Type_Chain_t * TailofTypeChain(ph_Type_Chain_t * phTypeChain) {

		if ( phTypeChain->next == NULL ) {
			return (phTypeChain);
		} else {
			return ( TailofTypeChain( phTypeChain->next ) );
		}
}

ph_Type_Chain_t * TailofStatusTypeChain(ph_Type_Chain_t * phTypeChain) {

		if ( phTypeChain->StatusTypeChainNext == NULL ) {
			return (phTypeChain);
		} else {
			return ( TailofStatusTypeChain( phTypeChain->StatusTypeChainNext ) );
		}
}

ph_Type_Chain_t * TailofAllTypeChain(ph_Type_Chain_t * phTypeChain) {

		if ( phTypeChain->AllTypeChainNext == NULL ) {
			return (phTypeChain);
		} else {
			return ( TailofAllTypeChain( phTypeChain->AllTypeChainNext ) );
		}
}

ph_Chain_t * TailofFieldChain(ph_Chain_t * phFieldChain) {

		if ( phFieldChain->next == NULL ) {
			return (phFieldChain);
		} else {
			return ( TailofFieldChain( phFieldChain->next ) );
		}
}

ph_Chain_t * TailofStatusFieldChain(ph_Chain_t * phFieldChain) {

		if ( phFieldChain->StatusFieldChainNext == NULL ) {
			return (phFieldChain);
		} else {
			return ( TailofStatusFieldChain( phFieldChain->StatusFieldChainNext ) );
		}
}
#ifdef DEBUG
void DumpStructs ( char * configname, ph_config_t * Config, char * HashArrayName, ph_KeyConfig_t ** KeyHashArray ) {
	if( !debug ) return;
#ifdef DUMPSTRUCTS
	DumpConfig( "", configname, Config);
	DumpKeyHashArray( "", HashArrayName, KeyHashArray, Config->hashSize);
#endif	// DUMPSTRUCTS
	return;
}

void DumpKeyHashArray( char * t1, char * title, ph_KeyConfig_t ** KeyHashArray, int LenArray) {
	if( !debug ) return;
	if ( KeyHashArray == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	if ( LenArray < 1 ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": (zero element array)\n", t1, title);
		return;
	}
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) ":" DBGBOLDYELLOW(%p) "\n", t1, title, KeyHashArray );
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	int found = 0;
	for (int i = 0; i < LenArray; i++) {
		if ( *(KeyHashArray+i) == NULL ) continue;
		WinFprintf(fp9, "%shash == " DBGBOLDRED(%i) ":\n", t1, i);
		snprintf(tempstr, (strlen(title)+48), "%s\[" DBGBOLDRED(%i) "]", title, i);
		DumpKeyConfigNext( tempstr2, tempstr,  KeyHashArray[i]);
		found++;
	}
	if ( !found ) {
		WinFprintf(fp9, DBGBOLDRED(-- no key hash entries --) "\n");
	} else {
		WinFprintf(fp9, DBGBOLDRED(-- %i key hash entries --) "\n", found);
	}
	WinFprintf(fp9, "\n");
	free(tempstr);
	free(tempstr2);
	return;
}

void DumpKeyConfigNext( char * t1, char * title, ph_KeyConfig_t * KeyConfig) {
	if( !debug ) return;
	if ( KeyConfig == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}

	DumpKeyConfig( t1, title,  KeyConfig);

	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->next) );
	DumpKeyConfigNext( t1, tempstr,  KeyConfig->next);
	free(tempstr);

	return;
}

void DumpKeyConfig( char * t1, char * title, ph_KeyConfig_t * KeyConfig) {
	if( !debug ) return;
	if ( KeyConfig == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) ":" DBGBOLDYELLOW(%p) "\n", t1, title, KeyConfig );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->key) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(KeyConfig->key) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->MailTo) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(KeyConfig->MailTo) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->Subject) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(KeyConfig->Subject) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->defaultPolicy) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, KeyConfig->defaultPolicy);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->currentPolicy) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, KeyConfig->currentPolicy);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->currentFormat) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, KeyConfig->currentFormat);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->phFilterChain) );
	DumpFilterChainNext( tempstr2, tempstr,  KeyConfig->phFilterChain);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->phFormatChain) );
	DumpFormatChainNext( tempstr2, tempstr,  KeyConfig->phFormatChain);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->phFormatChain) );
	DumpFormatMacroChainNext( tempstr2, tempstr,  KeyConfig->phFormatMacroChain);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->next) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(KeyConfig->next) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->statusKeyConfigNext) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(KeyConfig->statusKeyConfigNext) );

	free(tempstr);
	free(tempstr2);
	WinFprintf(fp9, "\n");
	return;
}

void DumpConfig( char * t1, char * title, ph_config_t * Config) {
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) ":" DBGBOLDYELLOW(%p) "\n", t1, title, Config );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->name) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->name) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->MTA) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->MTA) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->hashSize) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->hashSize);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->hashmask) "; \t" DBGBOLDYELLOW(%lu) "\n", t1, title, Config->hashmask);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->typehashSize) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->typehashSize);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->fieldhashSize) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->fieldhashSize);
	strcpy(tempstr, title);
	strcat(tempstr,"->phKeyConfig");
	DumpKeyConfig( tempstr2, tempstr, Config->phKeyConfig);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->TempTypeChain) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->TempTypeChain) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->statusKeyConfigHead) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->statusKeyConfigHead) );
//	strcpy(tempstr, title);
//	strcat(tempstr,"->statusKeyConfigHead");
//	DumpStatusKeyConfignext( tempstr2, tempstr, Config->statusKeyConfigHead);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->StatusTypeChainHead) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->StatusTypeChainHead) );
//	strcpy(tempstr, title);
//	strcat(tempstr, DBGBOLDGREEN(->phFilterChain) );
//	DumpStatusTypeChainNext( tempstr2, tempstr,  Config->StatusTypeChainHead);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->StatusFieldChainHead) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->StatusFieldChainHead) );
//	strcpy(tempstr, title);
//	strcat(tempstr, DBGBOLDGREEN(->StatusFieldChainHead) );
//	DumpStatusFieldChainNext( tempstr2, tempstr,  Config->StatusFieldChainHead);
	strcpy(tempstr, title);
	strcat(tempstr,"->CurrentFilterChain");
	DumpFilterChain( tempstr2, tempstr, Config->CurrentFilterChain);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->phKeyConfigSize) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->phKeyConfigSize);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->LastMailTo) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->LastMailTo) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->LastSubject) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->LastSubject) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s->LastDefault) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->LastDefault);
	WinFprintf(fp9, "\n");
	free(tempstr);
	free(tempstr2);
	return;
}

void DumpFilterChainNext( char * t1, char * title, ph_FilterChain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}

	DumpFilterChain( t1, title,  Config);

	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->next) );
	DumpFilterChainNext( t1, tempstr,  Config->next);
	free(tempstr);

	return;
}
void DumpFilterChain( char * t1, char * title, ph_FilterChain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) ":" DBGBOLDYELLOW(%p) "\n", t1, title, Config );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->label) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->label) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->value) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->value) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->PassOrReject) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->PassOrReject);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->TypeHashSize) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->TypeHashSize);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->DefaultTypeChain) );
	DumpTypeChainNext( tempstr2, tempstr,  Config->DefaultTypeChain);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->TypeHashArray) );
	DumpTypeChainHashArray( tempstr2, tempstr,  Config->TypeHashArray, phConfig.typehashSize);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->AllTypeChainHead) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->AllTypeChainHead) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->next) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->next) );

	free(tempstr);
	free(tempstr2);
	WinFprintf(fp9, "\n");
	return;
}

void DumpFormatChainNext( char * t1, char * title, ph_Chain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) " "  DBGBOLDRED(*************  DumpFormatChainNext TBD  *************) ":\n", t1, title);



	free(tempstr);
	free(tempstr2);
	WinFprintf(fp9, "\n");
	return;
}

void DumpFormatChain( char * t1, char * title, ph_Chain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) " "  DBGBOLDRED(*************  DumpFormatChain TBD  *************) ":\n", t1, title);



	free(tempstr);
	free(tempstr2);
	WinFprintf(fp9, "\n");
	return;
}

void DumpFormatMacroChainNext( char * t1, char * title, ph_Chain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) " "  DBGBOLDRED(*************  DumpFormatMacroChainNext TBD  *************) ":\n", t1, title);



	free(tempstr);
	free(tempstr2);
	WinFprintf(fp9, "\n");
	return;
}

void DumpFormatMacroChain( char * t1, char * title, ph_Chain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) " "  DBGBOLDRED(*************  DumpFormatMacroChain TBD  *************) ":\n", t1, title);



	free(tempstr);
	free(tempstr2);
	WinFprintf(fp9, "\n");
	return;
}

void DumpTypeChainNext( char * t1, char * title, ph_Type_Chain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}

	DumpTypeChain( t1, title,  Config);

	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->next) );
	DumpTypeChainNext( t1, tempstr,  Config->next);
	free(tempstr);

	return;
}

void DumpTypeChain( char * t1, char * title, ph_Type_Chain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) ":" DBGBOLDYELLOW(%p) "\n", t1, title, Config );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->Name) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->Name) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->Type) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->Type);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->Used) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->Used);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->lengthOfMaskArray) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->lengthOfMaskArray);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->FieldMaskArray) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->FieldMaskArray) );
	if ( Config->MatchMaskArray == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->MatchMaskArray) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->MatchMaskArray) );
	} else {
		for (int i=0; i<Config->lengthOfMaskArray; i++) {
			WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->MatchMaskArray) "[%i]; \t" DBGBOLDYELLOW(0x%016llx) "\n", t1, title, i, (void *)(Config->MatchMaskArray[i]) );
		}
	}
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->PassOrReject) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->PassOrReject);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->FieldHashSize) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->FieldHashSize);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->FieldHashArray) );
	DumpFieldChainHashArray( tempstr2, tempstr,  Config->FieldHashArray, phConfig.fieldhashSize);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->next) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->next) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->AllTypeChainNext) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->AllTypeChainNext) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->StatusTypeChainNext) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->StatusTypeChainNext) );

	free(tempstr);
	free(tempstr2);
	WinFprintf(fp9, "\n");
	return;
}

void DumpTypeChainHashArray( char * t1, char * title, ph_Type_Chain_t ** HashArray, int LenArray) {
	if( !debug ) return;
	if ( HashArray == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	if ( LenArray < 1 ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": (zero element array)\n", t1, title);
		return;
	}
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) ":" DBGBOLDYELLOW(%p) "\n", t1, title, HashArray );
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");

	int found = 0;
	for (int i = 0; i < LenArray; i++) {
		if ( *(HashArray+i) == NULL ) continue;
		WinFprintf(fp9, "%shash == " DBGBOLDRED(%i) ":\n", t1, i);
		snprintf(tempstr, (strlen(title)+48), "%s\[" DBGBOLDRED(%i) "]", title, i);
		DumpTypeChainNext( tempstr2, tempstr,  HashArray[i]);
		found++;
	}
	if ( !found ) {
		WinFprintf(fp9, "%s" DBGBOLDRED(-- no type chain entries --) "\n", t1);
	} else {
		WinFprintf(fp9, "%s" DBGBOLDRED(-- %i type chain entries --) "\n", t1, found);
	}
	WinFprintf(fp9, "\n");
	free(tempstr);
	free(tempstr2);
	return;
}

void DumpFieldChainNext( char * t1, char * title, ph_Chain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}

	DumpFieldChain( t1, title,  Config);

	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->next) );
	DumpFieldChainNext( t1, tempstr,  Config->next);
	free(tempstr);

	return;
}

void DumpFieldChain( char * t1, char * title, ph_Chain_t * Config){
	if( !debug ) return;
	if ( Config == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");

	WinFprintf(fp9, DBGBOLDGREEN(%s%s) ":" DBGBOLDYELLOW(%p) "\n", t1, title, Config );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->label) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->label) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->Type) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->Type);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->value) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, IFNULL(Config->value) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->FieldID) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->FieldID);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->PassOrReject) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->PassOrReject);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->MatchMaskIndex) "; \t" DBGBOLDYELLOW(%i) "\n", t1, title, Config->MatchMaskIndex);
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->MatchMask) "; \t" DBGBOLDYELLOW(0x%016llx) "\n", t1, title, (void *)(Config->MatchMask) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->ParentTypeRecord) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->ParentTypeRecord) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->next) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->next) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->StatusFieldChainNext) "; \t" DBGBOLDYELLOW(%p) "\n", t1, title, (void *)(Config->StatusFieldChainNext) );

	free(tempstr);
	free(tempstr2);
	WinFprintf(fp9, "\n");
	return;
}

void DumpFieldChainHashArray( char * t1, char * title, ph_Chain_t ** HashArray, int LenArray) {
	if( !debug ) return;
	if ( HashArray == NULL ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": " DBGBOLDRED(-null-) "\n", t1, title);
		return;
	}
	if ( LenArray < 1 ) {
		WinFprintf(fp9, DBGBOLDGREEN(%s%s) ": (zero element array)\n", t1, title);
		return;
	}

	WinFprintf(fp9, DBGBOLDGREEN(%s%s) ":" DBGBOLDYELLOW(%p) "\n", t1, title, HashArray );
	char * tempstr = (char *) calloc(strlen(title) + 50, 1);
	char * tempstr2 = (char *) calloc(strlen(t1) + 4, 1);
	strcpy(tempstr2, t1);
	strcat(tempstr2,"\t");

	int found = 0;
	for (int i = 0; i < LenArray; i++) {
		if ( *(HashArray+i) == NULL ) continue;
		WinFprintf(fp9, "%shash == " DBGBOLDRED(%i) ":\n", t1, i);
		snprintf(tempstr, (strlen(title)+48), "%s\[" DBGBOLDRED(%i) "]", title, i);
		DumpFieldChain( tempstr2, tempstr,  HashArray[i]);
		found++;
	}
	if ( !found ) {
		WinFprintf(fp9, "%s" DBGBOLDRED(-- no field chain entries --) "\n", t1);
	} else {
		WinFprintf(fp9, "%s" DBGBOLDRED(-- %i field chain entries --) "\n", t1, found);
	}
	WinFprintf(fp9, "\n");
	free(tempstr);
	free(tempstr2);

	return;

}

#endif	// DEBUG
