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
//#include "private.h"


extern const struct nv_list auparse_ids[];
extern int IsValidEmail(const char *email);


/* Local prototypes */
struct nv_pair
{
	char *name;
	char *value;
	char *option;
	int name_len;
	int value_len;
	int option_len;
};

struct kw_pair
{
	char *name;
	int (*parser)(struct nv_pair *, int, ph_config_t *);
	int max_options;
	int mask;
};


static char *get_line(FILE *f, char *buf, unsigned size, int *lineno,
		const char *file);
static int nv_split(char *buf, struct nv_pair *nv);
static struct kw_pair *kw_lookup(const char *val);
static int MTA_parser(struct nv_pair *nv, int line,
		ph_config_t *config);
static int hash_parser(struct nv_pair *nv, int line,
		ph_config_t *config);
static int key_parser(struct nv_pair *nv, int line,
		ph_config_t *config);
static int To_parser(struct nv_pair *nv, int line,
		ph_config_t *config);
static int Subject_parser(struct nv_pair *nv, int line,
		ph_config_t *config);
static int default_parser(struct nv_pair *nv, int line,
		ph_config_t *config);
static int filter_parser(struct nv_pair *nv, int line,
		ph_config_t *config);
static int format_parser(struct nv_pair *nv, int line, 
		ph_config_t *config);
static int sanity_check(ph_config_t *config, const char *file);
static char* valid_keywords( char **string );
static int nv_deesc(char *buf, char **name, int * name_len, char **ptr);
static void SetInputMode(modes newmode);
static int kw_unsetMask();
static int nv_lookup_name ( const nv_list_t *nv, char * myname );
static char * nv_lookup_option ( const nv_list_t *nv, int myoption );
static ph_KeyConfig_t * TailofKeyConfig(ph_KeyConfig_t * phKeyConfigs);
static ph_Chain_t * find_chain_end(ph_Chain_t * chain);

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
  { NULL,		0 }
};

static const struct nv_list filter_arg[] =
{
  {"pass",		FILPASS },
  {"reject",	FILREJECT },
  {"end",		FILEND },
  { NULL,		0 }
};

static const struct nv_list format_arg[] =
{
  {"macro",		FORMACRO },
  {"include",	FORINCLUDE },
  {"exclude",	FOREXCLUDE },
  {"end",		FOREND },
  { NULL,		0 }
};

/* The message mmode refers to where informational messages go
   0 - stderr, 1 - syslog, 2 - quiet. The default is quiet. */
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;
static char * defaultMTA = NULL;
static modes mode = HEADER;

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
void clear_phConfig(ph_config_t * phConfig)
{

	defaultMTA = (char *) malloc ( strlen( MTA_DEFAULT ) + 2 );
	strcpy( defaultMTA , MTA_DEFAULT );
	phConfig->MTA = defaultMTA ;
	phConfig->hashSize = HASH_DEFAULT;
	phConfig->phKeyConfig = NULL;
	phConfig->phKeyConfigSize = 0;
	phConfig->LastMailTo = NULL;
	phConfig->LastSubject = NULL;

	return;
}

int load_phConfig(ph_config_t *phConfig, char *file)
{
	int fd, rc, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[160];
	char *tmpString;

	clear_phConfig(phConfig);

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
		// convert line into name-value pair
		const struct kw_pair *kw;
		struct nv_pair nv;
		rc = nv_split(buf, &nv);
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


		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			if ( mode != FILTER && mode != FORMAT ) {
				audit_msg(LOG_ERR,
					"Unknown keyword \"%s\" in line %d of %s",
					nv.name, lineno, file);
				fclose(f);
				return 1;
			} else {
				xxxxxxxxxxxxx   process filters and formats here
			}
		} else { // is this keyword masked?
			if (kw->mask == 0) {
				if ( mode != FILTER && mode != FORMAT ) {
					audit_msg(LOG_ERR,
						"Out of order keyword \"%s\" in line %d of %s",
						nv.name, lineno, file);
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
			fclose(f);
			return 1;
		}

		/* dispatch to keyword's local parser */
		rc = kw->parser(&nv, lineno, phConfig);
		if (rc != 0) {
			fclose(f);
			return 1; // local parser puts message out
		}

		lineno++;
	}

	fclose(f);
	phConfig->name = strdup(basename(file));
	if (lineno > 1)
		return sanity_check(phConfig, file);
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

	nv->name = NULL;
	nv->value = NULL;
	nv->option = NULL;
	nv->name_len = 0;
	nv->value_len = 0;
	nv->option_len = 0;
	if ( buf == NULL ) return 5;
	if ( nv == NULL ) return 5;

	if ( strlen(buf) == 0 ) return 0; // If there's nothing, go to next line
	if ( strcspn(buf, " ") == strlen(buf) ) return 0; // If it's a all blank line, go to next line
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
	if ( strcspn(config->MTA, " ") == strlen(config->MTA) ) {
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

    str = (char *)calloc(1, nv->value_len + 1);
    // Handle empty string or string containing only whitespace
    if (str == NULL || *str == '\0') {
    	audit_msg(LOG_ERR, "hash value %s is missing - line %d", nv->value, line);
    	free(str);
    	return 1;
    }

    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }

    // If after skipping whitespace, the string is empty, it's not an integer
    if (*str == '\0') {
    	audit_msg(LOG_ERR, "hash value %s is blank - line %d", nv->value, line);
    	free(str);
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
    	free(str);
    	return 1;
    }

    // Check if the entire string was consumed by strtol (no non-numeric characters left)
    if (*endptr != '\0') {
    	audit_msg(LOG_ERR, "hash value %s Contains non-numeric characters after the number - line %d", nv->value, line);
    	free(str);
    	return 1;
    }
	free(str);

	// save the integer value
	config->hashSize = (int)val;

	return 0;
}


static int key_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	int i;
	unsigned long int result;
	unsigned long int sum = 0;
	ph_KeyConfig_t * tempKeyConfig, *KeyConfigTail;

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
	}

	// Allocate a new ph_KeyConfig struct
	config->phKeyConfig = tempKeyConfig = (ph_KeyConfig_t *) calloc(sizeof(ph_KeyConfig_t), 1);
	tempKeyConfig->key = strndup(nv->value,nv->value_len);
	tempKeyConfig->MailTo = strdup(config->LastMailTo);
	tempKeyConfig->defaultPolicy = PASS;
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

	return 0;
}

static int To_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	// if value is blank, there's nothing to do
	if (nv->value == NULL) return 0;
	if ( nv->value_len == 0 ) return 0;

	SetInputMode(KEY);

	char * tempValue;
	tempValue = strndup(nv->value, nv->value_len);

	if ( IsValidEmail(tempValue) == 0 ) {	// check the syntax of the email address
		audit_msg(LOG_WARNING, "The email address \"%s\" specified at line %d looks wrong, but it will be used anyway", tempValue, line);
	}

	// set the last used email in the config struct
	if ( config->LastMailTo != NULL ) free(config->LastMailTo);
	config->LastMailTo = tempValue;

	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		if ( config->phKeyConfig->MailTo != NULL ) free(config->phKeyConfig->MailTo);
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

	tempValue = strndup(nv->value, nv->value_len);

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
	if ( config->LastSubject != NULL ) free(config->LastSubject);
	config->LastSubject = tempValue;

	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		if ( config->phKeyConfig->Subject != NULL ) free(config->phKeyConfig->Subject);
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

	tempValue = strndup(nv->value, nv->value_len);
	// check for an option match
	int match = nv_lookup_name ( default_arg, tempValue );

	if ( match == 0 ) {
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
	ph_Chain_t * TempFilterChain;

	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;

	SetInputMode(FILTER);

	tempValue = strndup(nv->value, nv->value_len);
	// check for an option match
	int match = nv_lookup_name ( filter_arg, tempValue );

	if ( match == 0 ) {
		audit_msg(LOG_ERR, "\"%s\" not a valid filter option - line %d", tempValue, line);
		return 0;
	}
	free(tempValue);

	if ( match == FILEND ) {
		// tack wild card pass/reject at the end of the list to iplement the default feature
		if ( config->phKeyConfig->phFilterChain == NULL ) {
			// no chain, yet. create one and set the wild card
			TempFilterChain = config->phKeyConfig->phFilterChain = (ph_Chain_t *) calloc(sizeof(ph_Chain_t), 1);
		} else {
			// find the end of the chain
			TempFilterChain = find_chain_end(config->phKeyConfig->phFilterChain);
			TempFilterChain->next = (ph_Chain_t *) calloc(sizeof(ph_Chain_t), 1);
			TempFilterChain = TempFilterChain->next;
		}
		TempFilterChain->PassOrReject = config->phKeyConfig->defaultPolicy;
		TempFilterChain->label = strdup("*");
		TempFilterChain->value = strdup("*");
		// reset input mode
		SetInputMode(KEY);
		return 0;
	}
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

	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;

	SetInputMode(FORMAT);

	tempValue = strndup(nv->value, nv->value_len);
	// check for an option match
	int match = nv_lookup_name ( format_arg, tempValue );

	if ( match == 0 ) {
		audit_msg(LOG_ERR, "\"%s\" not a valid format option - line %d", tempValue, line);
		return 0;
	}
	free(tempValue);

	if ( match == FOREND ) {
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

	if ( chain->next == NULL ) {
		return;
	} else {
		free_chain( chain->next );
	}
	free( chain->label );
	free( chain->value );
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


void free_phKeyConfig(ph_KeyConfig_t * phKeyConfig) {

	if ( phKeyConfig->next == NULL ) {
		return;
	} else {
		free_phKeyConfig( phKeyConfig->next );
	}
	free( phKeyConfig->MailTo );
	free( phKeyConfig->Subject );
	free_chain( phKeyConfig->phFilterChain );
	free_chain( phKeyConfig->phFormatChain );
	free_chain( phKeyConfig->phFormatMacroChain );
	free ( phKeyConfig );
	phKeyConfig = NULL;

	return;
}

void free_phConfig(ph_config_t *phConfig)
{

	if (phConfig == NULL) return;

	if ( phConfig->MTA != NULL ) free(phConfig->MTA);
	if ( phConfig->phKeyConfig != NULL ) free_phKeyConfig( phConfig->phKeyConfig ); // free hash table
	phConfig->phKeyConfigSize = 0;
	if ( phConfig->LastMailTo != NULL ) free(phConfig->LastMailTo);
	if ( phConfig->LastSubject != NULL ) free(phConfig->LastSubject);

	return;
}

static char* valid_keywords( char **string ) {
	*string = (char *)malloc(2);
	**string = '\000';
	return (*string);
}

static int nv_deesc(char *buf, char **name, int * name_len, char **ptr) {
	int fldlen = 0;
	char * strStart;
	char * tmptr;

	strcpy(buf, buf+strcspn(buf, " ")); // skip all preceding blanks /////////////////  need to use memmove???...
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
		strStart = (*ptr)++;
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
			if ( (tmptr = strpbrk(*ptr, "\\ ")) == NULL ) { // end of string found
				fldlen = strlen(*ptr);
				break;
			}
			if ( *tmptr == ' ' ) { // blank space found
				fldlen = (int)(tmptr - strStart );
				break;
			}
			*ptr = memmove( tmptr, tmptr+1 , strlen(tmptr+1) + 1 ); // found a \ .. un-escape it
		}
	}
	*name = strStart;
	*name_len = fldlen;

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
		if (strcasecmp(myname, nv[i].name) == 0) break;
		i++;
	}

	return (nv[i].option);
}

static char * nv_lookup_option ( const nv_list_t *nv, int myoption ) {
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
