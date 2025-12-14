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
#include "phonehome.h"
#ifdef DEBUG
#include "debug2.h"
extern int WinFprintf(FILE *hf, const char * fmt,...);
#endif	// DEBUG
//#include "private.h"

#define IFNULL(ptr) ((ptr) == NULL ? "-null-" : (ptr))

extern int IsValidEmail(const char *email);
extern int parse_words(const char *buf, char ***args);
extern int create_timer(timer_list_t *td);

static char *get_line(FILE *f, char *buf, unsigned size, int *lineno, const char *file);
static struct kw_pair *kw_lookup(const char *val);
const struct opr_pair *opr_lookup(operator_t operator);
static int MTA_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int logdir_parser(struct nv_pair *nv, int line, ph_config_t *config);
static int tmpdir_parser(struct nv_pair *nv, int line, ph_config_t *config);
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
int equal_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config);
int notEqual_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config);
int greaterThan_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config);
int lessThan_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config);
int greaterThanEqualTo_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config);
int lessThanEqualTo_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config);
int regex_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config);
static void SetInputMode(modes newmode);
static int kw_unsetMask();
int nv_lookup_name ( const nv_list_t *nv, char * myname );
char * nv_lookup_option ( const nv_list_t *nv, int myoption );
static ph_KeyConfig_t * TailofKeyConfig(ph_KeyConfig_t * phKeyConfigs);
static ph_FilterChain_t * find_filterchain_end(ph_FilterChain_t * chain);
static ph_FormatChain_t * find_formatchain_end(ph_FormatChain_t * chain);
static ph_Type_Chain_t * TailofTypeChain(ph_Type_Chain_t * phTypeChain);
static ph_Type_Chain_t * TailofAllTypeChain(ph_Type_Chain_t * phTypeChain);
static ph_Type_Chain_t * CreatFilterTypeChain (ph_FilterChain_t * TempFilterChain, int match, char * tempValue, ph_config_t *config);
static ph_Type_Chain_t * CreatFormatTypeChain (ph_FormatChain_t * TempFormatChain, int match, char * tempValue, ph_config_t *config);
ph_Chain_t * TailofFieldChain(ph_Chain_t * phFieldChain);
static ph_KeyConfig_t * TailofStatusKeyConfig(ph_KeyConfig_t * phKeyConfigs);
static ph_Type_Chain_t * TailofStatusTypeChain(ph_Type_Chain_t * phTypeChain);
static ph_Chain_t * TailofStatusFieldChain(ph_Chain_t * phFieldChain);
static timer_list_t * TailofTimerChain(timer_list_t * TimerChain);
static void freeargs( char **args, int nargs );
static int checkVerbs( struct nv_pair *nv, int line, char * noun);
int checkOprArgs(ph_Chain_t * phFieldChain, auparse_state_t *au);
void free_chain(ph_Chain_t * chain);
void free_filterchain(ph_FilterChain_t * chain);
void freeStatusFieldChain(ph_Chain_t * chain);
void freeStatusTypeChain(ph_Type_Chain_t * chain);
void freeStatusKeyChain(ph_KeyConfig_t * chain);
static void freeTimerListChain(timer_list_t * chain);
void NukemAll ( ph_config_t *pphConfig );
static int WhitespaceSpan(char* str);
static long parse_time_with_suffix(const char *input_str, const char *noun, int line);
static long long parse_count_with_suffix(const char *str, int line);
static int parseRateOptions(struct nv_pair *nv, int line, unsigned long long int *count, unsigned long int *interval, unsigned long int *resetTime);
void DumpStructs ( char * configname, ph_config_t * Config, char * HashArrayName, ph_KeyConfig_t ** KeyHashArray );
void DumpKeyHashArray( char * t1, char * title, ph_KeyConfig_t ** KeyHashArray, int LenArray);
void DumpKeyConfigNext( char * t1, char * title, ph_KeyConfig_t * KeyConfig);
void DumpKeyConfig( char * t1, char * title, ph_KeyConfig_t * KeyConfig);
void DumpConfig( char * t1, char * title, ph_config_t * Config);
void DumpFilterChainNext( char * t1, char * title, ph_FilterChain_t * Config);
void DumpFilterChain( char * t1, char * title, ph_FilterChain_t * Config);
void DumpFormatChainNext( char * t1, char * title, ph_FormatChain_t * Config);
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
  {"key",				key_parser,				3,	1 },
  {"logdir",			logdir_parser,			0,	1 },
  {"tmpdir",			tmpdir_parser,			0,	1 },
  {"To",				To_parser,				0,	1 },
  {"Subject",			Subject_parser,			0,	1 },
  {"default",			default_parser,			3,	1 },
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
  {"include",	FORINCLUDE },
  {"logs",		FORLOGS },
  {"end",		FOREND },
  { NULL,		NOOPT }
};

const struct opr_pair operator_eval[] =
{
  {"==",	OPREQUAL,				equal_operator},
  {"=",		OPREQUAL,				equal_operator},
  {"!=",	OPRNOTEQUAL,			notEqual_operator},
  {">",		OPRGREATERTHAN,			greaterThan_operator},
  {"<",		OPRLESSTHAN,			lessThan_operator},
  {">=",	OPRGREATERTHANOREQUAL,	greaterThanEqualTo_operator},
  {"<=",	OPRLESSTHANOREQUAL,		lessThanEqualTo_operator},
  {":=",	OPRREGEX,				regex_operator},
  { NULL,	NOOPT,					NULL}
};

const struct nv_list operator_arg[] =
{
  {"==",	OPREQUAL },
  {"=",		OPREQUAL },
  {"!=",	OPRNOTEQUAL },
  {">",		OPRGREATERTHAN },
  {"<",		OPRLESSTHAN },
  {">=",	OPRGREATERTHANOREQUAL },
  {"<=",	OPRLESSTHANOREQUAL },
  {":=",	OPRREGEX },
  { NULL,	NOOPT }
};

const struct nv_list option_arg[] =
{
  {"?",		OPTINTERP },
  {"!?",	OPTNOINTERP },
  {"#",		OPTEVAL },
  {"~",		OPTQUOTE },
  { NULL,	NOOPT }
};

// The message mmode refers to where informational messages go
//   0 - stderr, 1 - syslog, 2 - quiet. The default is quiet.
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;
static const char * defaultMTA = MTA_DEFAULT ;
static const char * defaultMailTo = MAILTO_DEFAULT ;
static const char * defaultSubject = SUBJECT_DEFAULT ;
static const char * defaultLogDir = LOGDIR_DEFAULT ;
static const char * defaultTmpDir = TMPDIR_DEFAULT ;
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


// Set everything to its default value
void clear_phConfig(ph_config_t * pphConfig)
{

	pphConfig->MTA = (char *)defaultMTA ;
	pphConfig->hashSize = HASH_DEFAULT;
	pphConfig->hashmask = HASH_DEFAULT - 1;
	pphConfig->typehashSize = TYPE_HASH_DEFAULT;
	pphConfig->fieldhashSize = FIELD_HASH_DEFAULT;
	pphConfig->phKeyConfig = NULL;
	pphConfig->TempTypeChain = NULL;
	pphConfig->statusKeyConfigHead = NULL;
	pphConfig->StatusTypeChainHead = NULL;
	pphConfig->StatusFieldChainHead = NULL;
	pphConfig->CurrentFilterChain = NULL;
	pphConfig->phKeyConfigSize = 0;
	pphConfig->LastMailTo = (char *)defaultMailTo ;
	pphConfig->LastSubject = (char *)defaultSubject ;
	pphConfig->logDir = (char *)defaultLogDir;
	pphConfig->tmpDir = (char *)defaultTmpDir;
	pphConfig->LastDefault = -1;

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
//	char *tmpString;
	char **args = NULL;

	syslog(LOG_INFO, "loading config file");

	clear_phConfig(pphConfig);
	// open the file
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
	// check the file's permissions: owned by root, not world writable,
	// not symlink.
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
	// it's ok, read line by line
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
		if(debug) WinFprintf(fp9, "config line %i: " DBGBOLDYELLOW(%s) "\n", lineno, buf);
#endif	// DEBUG
		// convert line into name-value pair
		int nargs = parse_words(buf, &args);
#ifdef DEBUG
		int i;
		if(debug)  {
			WinFprintf(fp9, "parse_words returned " DBGBOLDRED(%i) "\n", nargs);
			if ( nargs > 0 ) {
				for (i = 0;i < nargs; i++) {
					if ( args[i] != NULL ) WinFprintf(fp9, "arg " DBGBOLDGREEN(%i) " == " DBGBOLDCYAN(%s) "\n", i, args[i]);
				}
			}
		}
#endif	// DEBUG
		if ( nargs == 0 ) {
			lineno++;
			continue;
		}
		if ( nargs < 0 ) return 1;
/*		if ( nargs > 4 ) {
			audit_msg(LOG_ERR, "Error - too many arguments on line %i in config file (%s) - ignoring", lineno , buf);
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "too many arguments on line " DBGBOLDGREEN(%i) " : " DBGBOLDRED(%s) "\n", lineno, buf);
#endif	// DEBUG
			freeargs( args, nargs );
			lineno++;
			continue;
		}*/
		// determine if operators or options are specified
		int valIndex = 1;
		int valOperator = 0;
		int valOption = 0;
		operator_t operator = NOOPT;
		options_t option = NOOPT;
		if ( nv_lookup_name ( operator_arg, args[valIndex] ) != NOOPT ) {
				valOperator = valIndex;
				valIndex++;
		}
		if ( nargs > valIndex + 1 ) { // we may have both an operator and an option
			if ( nv_lookup_name ( option_arg, args[valIndex+1] ) != NOOPT ) {
				valOption = valIndex+1;
			}
		}
/*		if ( nargs >= 4 ) { // we may have both an operator and an option
			valOperator = 1;
			valIndex = 2;
			valOption = 3;
		} else if ( nargs == 3 ) { // either args[1] is an operator or args[2] is an option - can't have both
			if ( nv_lookup_name ( operator_arg, args[1] ) != NOOPT ) {
				valOperator = 1;
				valIndex = 2;
			} else if ( nv_lookup_name ( option_arg, args[2] ) != NOOPT ) {
				valOption = 2;
			}
		} */ // nargs < 3 ==> neither an option or operator is specified
/*		if ( nargs > 2 && valOperator == 0 && valOption == 0 ) {
			audit_msg(LOG_ERR, "syntax error on line %i in config file (%s) - ignoring", lineno , buf);
#ifdef DEBUG
			if(debug) WinFprintf(fp9, DBGBOLDRED(syntax error on line %1) " in config file " DBGBOLDCYAN(%s) "\n", lineno, buf);
#endif	// DEBUG
			freeargs( args, nargs );
			lineno++;
			continue;
		} */
		// validate the operator
		if ( valOperator == 0 ) {
			operator = OPREQUAL;
		} else {
			operator = nv_lookup_name ( operator_arg, args[valOperator] );
			free ( args[valOperator] );
			args[valOperator] = NULL;
		}
/*		if ( operator == NOOPT ) {		// should be iposible - we already checked this above
			audit_msg(LOG_ERR, "Error - unrecognized operator (\"%s\") on line %i in config file - ignoring line", args[valOperator], lineno);
#ifdef DEBUG
			if(debug) WinFprintf(fp9, DBGBOLDRED(unrecognized operator %s) "on line " DBGBOLDCYAN(%i) "\n", args[valOperator], lineno);
#endif	// DEBUG
			freeargs( args, nargs );
			lineno++;
			continue;
		} */
		// validate the option
		if ( valOption == 0 ) {
			option = OPTINTERP;
		} else {
			option = nv_lookup_name ( option_arg, args[valOption] );
			free ( args[valOption] );
			args[valOption] = NULL;
		}
/*		if ( option == NOOPT ) {
			audit_msg(LOG_ERR, "Error - unrecognized option (\"%s\") on line %i in config file - ignoring line", args[valOption], lineno);
#ifdef DEBUG
			if(debug) WinFprintf(fp9, DBGBOLDRED(unrecognized option %s) " on line " DBGBOLDCYAN(%i) "\n", args[valOption], lineno);
#endif	// DEBUG
			freeargs( args, nargs );
			lineno++;
			continue;
		} */
		if ( ( option == OPTEVAL || option == OPTQUOTE ) && operator == OPRREGEX ) {
			audit_msg(LOG_ERR, "Error - illegal combination of option and operator on line %i in config file - ignoring line", lineno);
			audit_msg(LOG_ERR, "the %s option and %s operator may not me combined", nv_lookup_option ( option_arg, option ), nv_lookup_option ( operator_arg, operator ) );
#ifdef DEBUG
			if(debug) WinFprintf(fp9, DBGBOLDRED(illegal combination of option and operator) " on line " DBGBOLDCYAN(%i)
					", option = " DBGBOLDGREEN(%s) ", operator = " DBGBOLDGREEN(%s) "\n", lineno
					, nv_lookup_option( option_arg, option ), nv_lookup_option( operator_arg, operator ) );
#endif	// DEBUG
			freeargs( args, nargs );
			lineno++;
			continue;
		}

		nv.name = args[0];
		args[0] = NULL;	// keep freeargs from freeing this string
		nv.name_len = strlen(nv.name);
		nv.value = args[valIndex];
		args[valIndex] = NULL;	// keep freeargs from freeing this string
		nv.value_len = strlen(nv.value);
		nv.option = option;
		nv.valOption = valOption;
		nv.operator = operator;
		nv.valOperator = valOperator;
		nv.num_optional_args = nargs - ( MAX( valIndex, valOption) ) - 1;
		if ( nv.num_optional_args ) {
			nv.optional_args = args+MAX( valIndex, valOption)+1;
		} else {
			nv.optional_args = NULL;
		}
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "nv.name, nv.value = " DBGBOLDRED(%s) "," DBGBOLDRED(%s) "\n",nv.name, nv.value);
		if ( nv.operator == NOOPT ) {		// should be iposible - we already checked this above
			audit_msg(LOG_ERR, "Error - NOOPT operator on line %i in config file - this is a program bug", lineno);
			if(debug) WinFprintf(fp9, DBGBOLDRED(NOOPT operator) " on input line " DBGBOLDCYAN(%i) " detected at line %i in %s\n", lineno, __LINE__, __FILE__);
			freeargs( args, nargs );
			lineno++;
			continue;
		}
		if ( nv.option == NOOPT ) {		// should be iposible - we already checked this above
			audit_msg(LOG_ERR, "Error - NOOPT option on line %i in config file - this is a program bug", lineno);
			if(debug) WinFprintf(fp9, DBGBOLDRED(NOOPT option) " on input line " DBGBOLDCYAN(%i) " detected at line %i in %s\n", lineno, __LINE__, __FILE__);
			freeargs( args, nargs );
			lineno++;
			continue;
		}
#endif	// DEBUG
		// identify keyword or error
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
			} else {
				// in FILTER or FORMAT mode
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "Found potential auparse keyword \"" DBGBOLDRED(%s) "\" in line %d\n", nv.name, lineno);
				int auid;
				if(debug) {
					if ( strcmp(nv.name,"type") == 0 ) {
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
				goto Nextline;
			}
		} else { // is this keyword masked?
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "kw->name, kw->max_options, kw->mask = " DBGBOLDGREEN(%s) ", "
					 DBGBOLDGREEN(%i) ", " DBGBOLDGREEN(%i) "\n",kw->name, kw->max_options, kw->mask);
#endif	// DEBUG
			// Check number of options
			if ( nv.num_optional_args > kw->max_options ) {
				audit_msg(LOG_ERR, "Error - too many arguments on line %i in config file (%s) - ignoring", lineno , buf);
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "too many arguments on line " DBGBOLDGREEN(%i) " : " DBGBOLDRED(%s) "\n", lineno, buf);
#endif	// DEBUG
				freeargs( args, nargs );
				lineno++;
				continue;
			}
			// check for operator syntax error
			if ( nv.valOperator && nv.operator != OPREQUAL ) {
				audit_msg(LOG_ERR, "Error - illegal operator on line %i in config file (%s)... only \"=\" is permitted - ignoring entire line", lineno , buf);
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "illegal operator on line " DBGBOLDGREEN(%i) " : " DBGBOLDRED(%s) "\n", lineno, buf);
#endif	// DEBUG
				freeargs( args, nargs );
				lineno++;
				continue;
			}
			// check for filter option (should be none)
			if ( nv.valOption ) {
				audit_msg(LOG_ERR, "Error - field filter option on line %i in config file (%s) - ignoring entire line", lineno , buf);
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "illegal option on line " DBGBOLDGREEN(%i) " : " DBGBOLDRED(%s) "\n", lineno, buf);
#endif	// DEBUG
				freeargs( args, nargs );
				lineno++;
				continue;
			}
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
		}	// kw->name == NULL
		// dispatch to keyword's local parser
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
		freeargs( args, nargs );	// free all of the stuff malloc'ed in parse_words that we don't need any more
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
		// remove newline
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

const struct opr_pair *opr_lookup(operator_t operator) {
	int i = 0;
	while (operator_eval[i].name != NULL) {
		if (operator_eval[i].operator == operator) break;
		i++;
	}
	return &(operator_eval[i]);
}

static int MTA_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	int extra = 0;
	char * noun = "MTA";
	int iret;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

	// check for a port number separator
	if ( strpbrk(nv->value, ":") == NULL ) extra = 3;
	config->MTA = (char *)calloc(1, nv->value_len + 1 + extra);
	memmove( config->MTA, nv->value , nv->value_len );
    // check for a blank string

	if ( WhitespaceSpan(config->MTA) == strlen(config->MTA) ) {
    	audit_msg(LOG_ERR, "MTA value %s is blank - line %d", nv->value, line);
    	return 4;
    }
	if ( extra ) strcat(config->MTA, ":25"); // add default port 25 if none specified

	return 0;
}


static int logdir_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char * noun = "logdir";
	int iret;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

	config->logDir = strndup(nv->value,nv->value_len);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "Log files directory set to " DBGBOLDCYAN(%s) "\n",config->logDir);
#endif	// DEBUG

	return 0;
}


static int tmpdir_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char * noun = "tmpdir";
	int iret;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

	config->tmpDir = strndup(nv->value,nv->value_len);
	// make sure it ends with a "/"
	int lenname = strlen(config->tmpDir);
	if ( config->tmpDir[lenname-1] != '/' ) {
		config->tmpDir = (char*) realloc(config->tmpDir, lenname + 2 );
		strcat(config->tmpDir, "/");
	}
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "scratch file directory set to " DBGBOLDCYAN(%s) "\n",config->tmpDir);
#endif	// DEBUG

	return 0;
}


static int hash_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char * str;
    char *endptr;
    long val;
	char * noun = "hash";
	int iret;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

    str = nv->value;

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
	char * noun = "key";
	int iret;
	unsigned long long int count = 0;
	unsigned long int interval = 1;
	unsigned long int resetTime = 0;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

	if ( nv->num_optional_args ) {
		if ( (iret = parseRateOptions(nv, line, &count, &interval, &resetTime) ) )  {
			audit_msg(LOG_ERR, "Error: parsing rate and reset options for %s input on line %i in config file", noun, line);
			return iret;
		}
	}

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
	tempKeyConfig->key		= strndup(nv->value,nv->value_len);
	tempKeyConfig->MailTo	= strdup(config->LastMailTo);
	tempKeyConfig->Subject	= strdup(config->LastSubject);
	tempKeyConfig->defaultPolicy = config->LastDefault;
	if ( config->LastDefRateFilter != NULL ) {
		tempKeyConfig->defPolRateFilter = (rate_timer_t *) calloc(sizeof(rate_timer_t), 1);
		*(tempKeyConfig->defPolRateFilter) = *(config->LastDefRateFilter);	// assumes c++ struct copy construct available
		if ( tempKeyConfig->defPolRateFilter->resetTime ) {
			timer_list_t * timer_data = (timer_list_t *)calloc( sizeof(timer_list_t), 1);
			char * timerName = (char *)malloc( strlen("default") + strlen(tempKeyConfig->key) + 2);
			strcpy(timerName, "default");
			strcat(timerName," ");
			strcat(timerName,tempKeyConfig->key);
			timer_data->name = timerName;
			timer_data->mask = &(tempKeyConfig->defPolRateFilter->TimeoutMask);
			timer_data->parentRateTimerStruct = tempKeyConfig->defPolRateFilter;
			create_timer(timer_data);
			if ( config->StatusTimerListHead == NULL ) {
				config->StatusTimerListHead = timer_data;
			} else {
				TailofTimerChain(config->StatusTimerListHead)->next = timer_data;
			}
			tempKeyConfig->defPolRateFilter->timer = timer_data;
		}
	}
	tempKeyConfig->currentPolicy = -1;
	tempKeyConfig->currentFormat = -1;
	if ( nv->num_optional_args ) {
		tempKeyConfig->keyRateFilter = (rate_timer_t *) calloc(sizeof(rate_timer_t), 1);
		tempKeyConfig->keyRateFilter->count		= count;
		tempKeyConfig->keyRateFilter->currentCount	= 0;
		memset(&(tempKeyConfig->keyRateFilter->countStartTime), 0, sizeof(time_t));
		tempKeyConfig->keyRateFilter->interval		= interval;
		tempKeyConfig->keyRateFilter->resetTime	= resetTime;
		tempKeyConfig->keyRateFilter->TimeoutMask	= 0;
		if ( resetTime ) {
			timer_list_t * timer_data = (timer_list_t *)calloc( sizeof(timer_list_t), 1);
			char * timerName = (char *)malloc( strlen(noun) + strlen(tempKeyConfig->key) + 2);
			strcpy(timerName, noun);
			strcat(timerName," ");
			strcat(timerName,tempKeyConfig->key);
			timer_data->name = timerName;
			timer_data->mask = &(tempKeyConfig->keyRateFilter->TimeoutMask);
			timer_data->parentRateTimerStruct = tempKeyConfig->keyRateFilter;
			create_timer(timer_data);
			if ( config->StatusTimerListHead == NULL ) {
				config->StatusTimerListHead = timer_data;
			} else {
				TailofTimerChain(config->StatusTimerListHead)->next = timer_data;
			}
			tempKeyConfig->keyRateFilter->timer = timer_data;
		}
	}
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
	char * noun = "To";
	int iret;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

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
	char * noun = "Subject";
	int iret;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

	SetInputMode(KEY);

	tempValue = strdup(nv->value);

	// check for the string "$hostname" if we find it, substitute our hostname
	if ( (result1 = strstr(tempValue, "$hostname")) != NULL ) {
		if ( myhostname != NULL ) {
			char *temp2;
			temp2 = tempValue;
			tempValue = (char *) malloc(strlen(temp2) - strlen("$hostname") + strlen(myhostname) + 2 );
			int numtocpy = (int)(result1-temp2);
			strncpy(tempValue, temp2, numtocpy );
			*(tempValue+numtocpy) = '\000';
			strcat(tempValue, myhostname);
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
	char * noun = "default";
	int iret;
	unsigned long long int count = 0;
	unsigned long int interval = 1;
	unsigned long int resetTime = 0;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

	if ( nv->num_optional_args ) {
		if ( (iret = parseRateOptions(nv, line, &count, &interval, &resetTime) ) )  {
			audit_msg(LOG_ERR, "Error: parsing rate and reset options for %s input on line %i in config file", noun, line);
			return iret;
		}
	}

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

	if ( config->LastDefRateFilter != NULL ) free(config->LastDefRateFilter);
	config->LastDefRateFilter = NULL;
	if ( nv->num_optional_args ) {
		config->LastDefRateFilter = (rate_timer_t *) calloc(sizeof(rate_timer_t), 1);
		config->LastDefRateFilter->count		= count;
		config->LastDefRateFilter->currentCount	= 0;
		memset(&(config->LastDefRateFilter->countStartTime), 0, sizeof(time_t));
		config->LastDefRateFilter->interval		= interval;
		config->LastDefRateFilter->resetTime	= resetTime;
		config->LastDefRateFilter->TimeoutMask	= 0;
	}

	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		config->phKeyConfig->defaultPolicy = match;
		if ( config->LastDefRateFilter != NULL ) {
			config->phKeyConfig->defPolRateFilter = (rate_timer_t *) calloc(sizeof(rate_timer_t), 1);
			*(config->phKeyConfig->defPolRateFilter) = *(config->LastDefRateFilter);	// assumes c++ struct copy construct available
			if ( resetTime ) {
				timer_list_t * timer_data = (timer_list_t *)calloc( sizeof(timer_list_t), 1);
				char * timerName = (char *)malloc( strlen(noun) + strlen(config->phKeyConfig->key) + 2);
				strcpy(timerName, noun);
				strcat(timerName," ");
				strcat(timerName,config->phKeyConfig->key);
				timer_data->name = timerName;
				timer_data->mask = &(config->phKeyConfig->defPolRateFilter->TimeoutMask);
				timer_data->parentRateTimerStruct = config->phKeyConfig->defPolRateFilter;
				create_timer(timer_data);
				if ( config->StatusTimerListHead == NULL ) {
					config->StatusTimerListHead = timer_data;
				} else {
					TailofTimerChain(config->StatusTimerListHead)->next = timer_data;
				}
				config->phKeyConfig->defPolRateFilter->timer = timer_data;
			}
		}
	}

	return 0;
}


static int filter_parser(struct nv_pair *nv, int line, ph_config_t *config)
{
	char *tempValue;
	ph_FilterChain_t * TempFilterChain;
	char * noun = "filter";
	int iret;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

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
	ph_FormatChain_t * TempFormatChain;
	char * noun = "format";
	int iret;

	if ( ( iret = checkVerbs( nv, line, noun) ) ) return iret;

	SetInputMode(FORMAT);

	tempValue = strdup(nv->value);
	// check for an option match
	int match = nv_lookup_name ( format_arg, tempValue );
	if ( match == NOOPT ) {
		audit_msg(LOG_ERR, "\"%s\" not a valid format option - line %d", tempValue, line);
		free(tempValue);
		return 0;
	}

	// no formatchain, yet. create one
	if ( config->phKeyConfig->phFormatChain == NULL ) {
		TempFormatChain = config->phKeyConfig->phFormatChain = (ph_FormatChain_t *) calloc(sizeof(ph_FormatChain_t), 1);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "new format chain struct created at "DBGBOLDCYAN(%p) "\n",TempFormatChain);
#endif	// DEBUG
	} else {
		TempFormatChain = find_formatchain_end(config->phKeyConfig->phFormatChain);
		TempFormatChain->next = (ph_FormatChain_t *) calloc(sizeof(ph_FormatChain_t), 1);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "new format chain struct created at " DBGBOLDCYAN(%p) " added at the end of the chain following " DBGBOLDCYAN(%p) "\n",TempFormatChain->next ,TempFormatChain);
#endif	// DEBUG
		TempFormatChain = TempFormatChain->next;
	}
	TempFormatChain->TypeHashSize = config->typehashSize;
	TempFormatChain->label = strndup(nv->name,nv->name_len);
	TempFormatChain->value = tempValue;
	if ( match == FORLOGS ) {
		TempFormatChain->AttachLogs = 1;
	} else {
		TempFormatChain->IncludeOrExclude = match;
	}
	currentRecordType = 0;	// reset the record type to none

	if ( match == FOREND ) {
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDCYAN(FORMAT END detected) "\n");
#endif	// DEBUG
		// tack wild card pass/reject at the end of the list to iplement the default feature
		TempFormatChain->next = (ph_FormatChain_t *) calloc(sizeof(ph_FormatChain_t), 1);
		TempFormatChain = TempFormatChain->next;
		TempFormatChain->IncludeOrExclude = config->phKeyConfig->defaultFormat;
		TempFormatChain->label = strdup("*");
		TempFormatChain->value = strdup("*");
		// reset input mode
		SetInputMode(KEY);
		return 0;
	}
	// must be a pass or reject command: set TempFilterChain
	TempFormatChain->IncludeOrExclude = match;
	// set it in the current phKeyConfig, too (if one exists)
	if ( config->phKeyConfig != NULL ) {
		config->phKeyConfig->currentFormat = match;
	} else {
		audit_msg(LOG_ERR, "Out of order filter option; must define key before filter - line %d", line);
		return 1;
	}

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
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "no type card prior to field filters\n");
#endif	// DEBUG
			audit_msg(LOG_ERR, "\"%s\" at line %d appears to be a field match request - however, there has been no record type defined - it will be ignored", nv->name , line);
			free(tempValue);
			return 0;
		}
		// must be a non-type field match request
		// check the name to see if it makes sense
		if ( ( auid = nv_lookup_name ( auparse_ids, nv->name ) ) == NOOPT ) {
			audit_msg(LOG_WARNING, "\"%s\" at line %d is an unknown audit field - we will try to match it anyway", nv->name , line);
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
		TempFieldChain->operator = nv->operator;
		if ( nv->operator == OPRREGEX ) { // compile the regex
			TempFieldChain->regexcomp = (regex_t *)calloc(sizeof(regex_t), 1);
			int iret = regcomp(TempFieldChain->regexcomp, TempFieldChain->value, 0);
			if (iret) {
				char msgbuf[100];
				regerror(iret, TempFieldChain->regexcomp, msgbuf, sizeof(msgbuf));
				audit_msg(LOG_ERR, "error compiling the regex for %s field on %s record for key=%s : %s",
						TempFieldChain->label, TempTypeChain->Name, config->phKeyConfig->key  ,msgbuf);
#ifdef DEBUG
				if(debug) WinFprintf(fp9, DBGBOLDRED(error compiling the regex) " for field %s on %s record for key=%s : " DBGBOLDRED(%s)  "\n",
						TempFieldChain->label, TempTypeChain->Name, config->phKeyConfig->key  ,msgbuf);
#endif	// DEBUG

				audit_msg(LOG_WARNING, "\"%s\" at line %d is an unknown audit field - we will try to match it anyway", nv->name , line);
				TempFieldChain->operator = OPREQUAL;	// disables the regex call
			}
		}
		TempFieldChain->option = nv->option;
		if ( TempFieldChain->option == OPTEVAL ) {	// if this field is to be evaluated, set TempFieldChain->intValue
				if ( nv->name_len != 0 ) {
					char * endptr;
				    // Convert the string to a long integer
				    long int val = strtol(TempFieldChain->value, &endptr, 10);
				    if (*endptr == '\0' && endptr != TempFieldChain->value) {
				    	TempFieldChain->intValue = val;
				    } else {
				    	audit_msg(LOG_ERR, "you specified the evaluate option for \"%s\" at line %d, however, the value you specify is %s "
				    			"which does not appear to be an integer -- field ignored", nv->name , line, TempFieldChain->value);
#ifdef DEBUG
				    	if(debug) WinFprintf(fp9, DBGBOLDRED(unable to evaluate %s) " at line " DBGBOLDCYAN(%d) ", the value is "
				    			DBGBOLDRED(%s) "\n", nv->name , line, TempFieldChain->value);
#endif	// DEBUG
				    	free(tempValue);
				    	return 0;
				    }
				}
		}
		if ( TempFieldChain->option == OPTQUOTE ) {	// if this field is to be quoted, add quotes to TempFieldChain->value
				if ( TempFieldChain->value != NULL ) {
					char * tmpstr = (char *)calloc(strlen(TempFieldChain->value) + 3, 1);
					strcpy(tmpstr, "\"");	// initial quote
				    strcat(tmpstr,TempFieldChain->value);	// copy the string
				    strcat(tmpstr, "\"");	// final quote
				    free(TempFieldChain->value);
				    TempFieldChain->value = tmpstr;
				    tmpstr = NULL;
#ifdef DEBUG
				    if(debug) WinFprintf(fp9, "value for " DBGBOLDRED(%s) " at line " DBGBOLDCYAN(%d) " changed to "
				    			DBGBOLDGREEN(%s) "\n", nv->name , line, TempFieldChain->value);
#endif	// DEBUG
				}
		}
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


ph_Type_Chain_t * CreatFormatTypeChain (ph_FormatChain_t * TempFormatChain, int match, char * tempValue, ph_config_t *config) {
	ph_Type_Chain_t * TempTypeChain;
	ph_Type_Chain_t * TypeChainTail;
	int i;

	if ( TempFormatChain->TypeHashArray == NULL ) {
		TempFormatChain->TypeHashArray = (ph_Type_Chain_t **) calloc(sizeof(ph_Type_Chain_t *), TempFormatChain->TypeHashSize);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "TypeHashArray created at " DBGBOLDCYAN(%p) " with length " DBGBOLDGREEN(%i) " for the " DBGBOLDRED(%s) " format struct at " DBGBOLDCYAN(%p) "\n",
				TempFormatChain->TypeHashArray, TempFormatChain->TypeHashSize, TempFormatChain->value, TempFormatChain);
#endif	// DEBUG
	}

	// Allocate a new ph_Type_Chain struct
	TempTypeChain = (ph_Type_Chain_t *) calloc(sizeof(ph_Type_Chain_t), 1);
	TempTypeChain->Name = tempValue;
	TempTypeChain->Type = match;
	TempTypeChain->FieldHashSize = config->fieldhashSize;
	// add the new type struct to the linked list for this filter
	if ( TempFormatChain->AllTypeChainHead == NULL ) {
		TempFormatChain->AllTypeChainHead = TempTypeChain;
	} else {
		TailofAllTypeChain(TempFormatChain->AllTypeChainHead)->AllTypeChainNext = TempTypeChain;
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
	i = match % TempFormatChain->TypeHashSize;
#ifdef DEBUG
	if ( TempFormatChain->TypeHashArray == NULL ) {
		if (debug) WinFprintf(fp9, DBGBOLDRED(TempFormatChain->TypeHashArray == NULL) " at line %d in %s\n", __LINE__, __FILE__);
		audit_msg(LOG_ERR,"phonehome audit plugin is exiting due to program bug at line %d in %s", __LINE__, __FILE__);
	}
#endif	// DEBUG
	// Check for collision
	if ( TempFormatChain->TypeHashArray[i] != NULL ) {
		// find the end of the linked list...
		TypeChainTail = TailofTypeChain(TempFormatChain->TypeHashArray[i]);
		TypeChainTail->next = TempTypeChain;
	} else {
		TempFormatChain->TypeHashArray[i] = TempTypeChain;
	}
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDGREEN(%s) " hashed to " DBGBOLDGREEN(%i) " ie, hash table entry = " DBGBOLDCYAN(%p) "\n",tempValue, i, &(TempFormatChain->TypeHashArray[i]) );
#endif	// DEBUG
	return (TempTypeChain);
}


static int format_rule_parser(struct nv_pair *nv, int line, ph_config_t *config) {
	char *tempValue;
	int match;
	int auid;
	int i;
	long long int sum = 0;
	ph_FormatChain_t * TempFormatChain;
	ph_Type_Chain_t * TempTypeChain;
	ph_Chain_t * TempFieldChain;
	ph_Chain_t * FieldChainTail;

	// if value is blank, there's nothing to do
	if ( nv->value == NULL ) return 0;
	if ( nv->value_len == 0 ) return 0;
	tempValue = strdup(nv->value);

	if ( config->phKeyConfig->phFormatChain == NULL ) {
		audit_msg(LOG_ERR, "\"%s %s\" at line %d appears to be out of order - expecting a \"format\" directive", nv->name, tempValue, line);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "\"%s %s\" at line %d appears to be out of order - expecting a \"format\" directive", nv->name, tempValue, line);
#endif	// DEBUG
		free(tempValue);
		return 0;
	}
	// find the last thing we worked on...
	TempTypeChain = config->TempTypeChain;
	// find the current format chain tail
	TempFormatChain = find_formatchain_end(config->phKeyConfig->phFormatChain);
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
		// create a type format table entry
		TempTypeChain = CreatFormatTypeChain (TempFormatChain, match, tempValue, config);
		config->TempTypeChain = TempTypeChain;
		// make sure that the format chain
	} else {
		// check if we have encountered a type card, yet
		if ( currentRecordType == 0 ) {
			// this appears to be a field match request, but the user didn't say which record type to expect it on
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "no type card prior to field formats\n");
#endif	// DEBUG
			audit_msg(LOG_ERR, "\"%s\" at line %d appears to be a field match request - however, there has been no record type defined - it will be ignored", nv->name , line);
			free(tempValue);
			return 0;
		}
		// must be a non-type field match request
		// check the name to see if it makes sense
		if ( ( auid = nv_lookup_name ( auparse_ids, nv->name ) ) == NOOPT ) {
			audit_msg(LOG_WARNING, "\"%s\" at line %d is an unknown audit field - we will try to match it anyway", nv->name , line);
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


// This function is where we do the integrated check of the audispd config
// options. At this point, all fields have been read. Returns 0 if no
// problems and 1 if problems detected.
static int sanity_check(ph_config_t *config, const char *file)
{
	// Error checking
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

int equal_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config) {

#ifdef DEBUG
	int iret;
	if ( ( iret = checkOprArgs(phFieldChain, au) ) ) {
		audit_msg(LOG_ERR, "error processing the equal_operator for event %i", auparse_get_line_number(au));
		return ( iret );
	}

	if(debug) WinFprintf(fp9, "comparing " DBGBOLDRED(%s) " equal to " DBGBOLDGREEN(%s)
			" or " DBGBOLDGREEN(%s) "\n",
			phFieldChain->value, auparse_interpret_field(au), auparse_get_field_str(au));
#endif	// DEBUG

	switch (phFieldChain->option) {
		case OPTINTERP:
			if ( strcmp(phFieldChain->value, auparse_interpret_field(au)) == 0 ) return 1;
			break;
		case OPTEVAL:
		case OPTQUOTE:
		case OPTNOINTERP:
			if ( strcmp(phFieldChain->value, auparse_get_field_str(au)) == 0 ) return 1;
			break;
		default:
			break;
	}

	return 0;
}

int notEqual_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config) {

#ifdef DEBUG
	int iret;
	if ( ( iret = checkOprArgs(phFieldChain, au) ) ) {
		audit_msg(LOG_ERR, "error processing the notEqual_operator for event %i", auparse_get_line_number(au));
		return ( iret );
	}

	if(debug) WinFprintf(fp9, "comparing " DBGBOLDRED(%s) " not equal to " DBGBOLDGREEN(%s)
			" or " DBGBOLDGREEN(%s) "\n",
			phFieldChain->value, auparse_interpret_field(au), auparse_get_field_str(au));
#endif	// DEBUG

	switch (phFieldChain->option) {
		case OPTINTERP:
			if ( strcmp(phFieldChain->value, auparse_interpret_field(au)) != 0 ) return 1;
			break;
		case OPTEVAL:
		case OPTQUOTE:
		case OPTNOINTERP:
			if ( strcmp(phFieldChain->value, auparse_get_field_str(au)) != 0 ) return 1;
			break;
		default:
			break;
	}

	return 0;
}

int greaterThan_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config) {
	static long long int errcnt = 0;

#ifdef DEBUG
	int iret;
	if ( ( iret = checkOprArgs(phFieldChain, au) ) ) {
		audit_msg(LOG_ERR, "error processing the greaterThan_operator for event %i", auparse_get_line_number(au));
		return ( iret );
	}

	if(debug) WinFprintf(fp9, "comparing " DBGBOLDRED(%s) " < " DBGBOLDGREEN(%s)
			" or " DBGBOLDGREEN(%s) "\n",
			phFieldChain->value, auparse_interpret_field(au), auparse_get_field_str(au));
#endif	// DEBUG

	switch (phFieldChain->option) {
		case OPTINTERP:
			if ( strcmp(auparse_get_field_str(au), phFieldChain->value) > 0 ) return 1;
			break;
		case OPTQUOTE:
		case OPTNOINTERP:
			if ( strcmp(auparse_get_field_str(au), phFieldChain->value) > 0 ) return 1;
			break;
		case OPTEVAL:
			auparse_type_t field_type = auparse_get_field_type(au);
			if (field_type == AUPARSE_TYPE_UNCLASSIFIED) {
				const char * strval = auparse_get_field_str(au);
				if ( strval != NULL ) {
					if ( strlen(strval) != 0 ) {
						char * endptr;
					    // Convert the string to a long integer
					    long int val = strtol(strval, &endptr, 10);
					    if (*endptr == '\0' && endptr != strval) {
					    	if ( val > phFieldChain->intValue ) return 1;
					    }
					}
				}
			} else {
				if ( errcnt < 5 ) {
					audit_msg(LOG_ERR, "error processing the > operator for the %s field "
							"(value = %s) in event %i - this does not appear to be an integer number",
							phFieldChain->label, auparse_get_field_str(au), auparse_get_serial(au));
					audit_msg(LOG_ERR, "this is a problem in your %s config file", config->name);
					audit_msg(LOG_ERR, "you apparently have an eval option (#) on your %s filter and "
							"%s is not an integer", phFieldChain->label, phFieldChain->label);
				}
				if ( errcnt == 4 ) audit_msg(LOG_ERR, "Note: future processing of this error message is disabled. "
						"Restart auditd to re-enable");
				errcnt++;
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "the " DBGBOLDRED(%s) " field on the " DBGBOLDRED(%s)
						" record is not " DBGBOLDGREEN(AUPARSE_TYPE_UNCLASSIFIED) "\n",
						phFieldChain->label, phFieldChain->ParentTypeRecord->Name );
#endif	// DEBUG
				return ( -100 );
			}
			break;
		default:
			break;
	}

	return 0;
}

int lessThan_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config) {
	static long long int errcnt = 0;

#ifdef DEBUG
	int iret;
	if ( ( iret = checkOprArgs(phFieldChain, au) ) ) {
		audit_msg(LOG_ERR, "error processing the lessThan_operator for event %i", auparse_get_line_number(au));
		return ( iret );
	}

	if(debug) WinFprintf(fp9, "comparing " DBGBOLDRED(%s) " > " DBGBOLDGREEN(%s)
			" or " DBGBOLDGREEN(%s) "\n",
			phFieldChain->value, auparse_interpret_field(au), auparse_get_field_str(au));
#endif	// DEBUG

	switch (phFieldChain->option) {
		case OPTINTERP:
			if ( strcmp(auparse_get_field_str(au), phFieldChain->value) < 0 ) return 1;
			break;
		case OPTQUOTE:
		case OPTNOINTERP:
			if ( strcmp(auparse_get_field_str(au), phFieldChain->value) < 0 ) return 1;
			break;
		case OPTEVAL:
			auparse_type_t field_type = auparse_get_field_type(au);
			if (field_type == AUPARSE_TYPE_UNCLASSIFIED) {
				const char * strval = auparse_get_field_str(au);
				if ( strval != NULL ) {
					if ( strlen(strval) != 0 ) {
						char * endptr;
					    // Convert the string to a long integer
					    long int val = strtol(strval, &endptr, 10);
					    if (*endptr == '\0' && endptr != strval) {
					    	if ( val < phFieldChain->intValue ) return 1;
					    }
					}
				}
			} else {
				if ( errcnt < 5 ) {
					audit_msg(LOG_ERR, "error processing the < operator for the %s field "
							"(value = %s) in event %i - this does not appear to be an integer number",
							phFieldChain->label, auparse_get_field_str(au), auparse_get_serial(au));
					audit_msg(LOG_ERR, "this is a problem in your %s config file", config->name);
					audit_msg(LOG_ERR, "you apparently have an eval option (#) on your %s filter and "
							"%s is not an integer", phFieldChain->label, phFieldChain->label);
				}
				if ( errcnt == 4 ) audit_msg(LOG_ERR, "Note: future processing of this error message is disabled. "
						"Restart auditd to re-enable");
				errcnt++;
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "the " DBGBOLDRED(%s) " field on the " DBGBOLDRED(%s)
						" record is not " DBGBOLDGREEN(AUPARSE_TYPE_UNCLASSIFIED) "\n",
						phFieldChain->label, phFieldChain->ParentTypeRecord->Name );
#endif	// DEBUG
				return ( -100 );
			}
			break;
		default:
			break;
	}

	return 0;
}

int greaterThanEqualTo_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config) {
	static long long int errcnt = 0;

#ifdef DEBUG
	int iret;
	if ( ( iret = checkOprArgs(phFieldChain, au) ) ) {
		audit_msg(LOG_ERR, "error processing the greaterThanEqualTo_operator for event %i", auparse_get_line_number(au));
		return ( iret );
	}

	if(debug) WinFprintf(fp9, "comparing " DBGBOLDRED(%s) " <= " DBGBOLDGREEN(%s)
			" or " DBGBOLDGREEN(%s) "\n",
			phFieldChain->value, auparse_interpret_field(au), auparse_get_field_str(au));
#endif	// DEBUG

	switch (phFieldChain->option) {
		case OPTINTERP:
			if ( strcmp(auparse_get_field_str(au), phFieldChain->value) >= 0 ) return 1;
			break;
		case OPTQUOTE:
		case OPTNOINTERP:
			if ( strcmp(auparse_get_field_str(au), phFieldChain->value) >= 0 ) return 1;
			break;
		case OPTEVAL:
			auparse_type_t field_type = auparse_get_field_type(au);
			if (field_type == AUPARSE_TYPE_UNCLASSIFIED) {
				const char * strval = auparse_get_field_str(au);
				if ( strval != NULL ) {
					if ( strlen(strval) != 0 ) {
						char * endptr;
					    // Convert the string to a long integer
					    long int val = strtol(strval, &endptr, 10);
					    if (*endptr == '\0' && endptr != strval) {
					    	if ( val >= phFieldChain->intValue ) return 1;
					    }
					}
				}
			} else {
				if ( errcnt < 5 ) {
					audit_msg(LOG_ERR, "error processing the >= operator for the %s field "
							"(value = %s) in event %i - this does not appear to be an integer number",
							phFieldChain->label, auparse_get_field_str(au), auparse_get_serial(au));
					audit_msg(LOG_ERR, "this is a problem in your %s config file", config->name);
					audit_msg(LOG_ERR, "you apparently have an eval option (#) on your %s filter and "
							"%s is not an integer", phFieldChain->label, phFieldChain->label);
				}
				if ( errcnt == 4 ) audit_msg(LOG_ERR, "Note: future processing of this error message is disabled. "
						"Restart auditd to re-enable");
				errcnt++;
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "the " DBGBOLDRED(%s) " field on the " DBGBOLDRED(%s)
						" record is not " DBGBOLDGREEN(AUPARSE_TYPE_UNCLASSIFIED) "\n",
						phFieldChain->label, phFieldChain->ParentTypeRecord->Name );
#endif	// DEBUG
				return ( -100 );
			}
			break;
		default:
			break;
	}

	return 0;
}

int lessThanEqualTo_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config) {
	static long long int errcnt = 0;

#ifdef DEBUG
	int iret;
	if ( ( iret = checkOprArgs(phFieldChain, au) ) ) {
		audit_msg(LOG_ERR, "error processing the lessThanEqualTo_operator for event %i", auparse_get_line_number(au));
		return ( iret );
	}

	if(debug) WinFprintf(fp9, "comparing " DBGBOLDRED(%s) " >= " DBGBOLDGREEN(%s)
			" or " DBGBOLDGREEN(%s) "\n",
			phFieldChain->value, auparse_interpret_field(au), auparse_get_field_str(au));
#endif	// DEBUG

	switch (phFieldChain->option) {
		case OPTINTERP:
			if ( strcmp(auparse_get_field_str(au), phFieldChain->value) <= 0 ) return 1;
			break;
		case OPTNOINTERP:
		case OPTQUOTE:
			if ( strcmp(auparse_get_field_str(au), phFieldChain->value) <= 0 ) return 1;
			break;
		case OPTEVAL:
			auparse_type_t field_type = auparse_get_field_type(au);
			if (field_type == AUPARSE_TYPE_UNCLASSIFIED) {
				const char * strval = auparse_get_field_str(au);
				if ( strval != NULL ) {
					if ( strlen(strval) != 0 ) {
						char * endptr;
					    // Convert the string to a long integer
					    long int val = strtol(strval, &endptr, 10);
					    if (*endptr == '\0' && endptr != strval) {
					    	if ( val <= phFieldChain->intValue ) return 1;
					    }
					}
				}
			} else {
				if ( errcnt < 5 ) {
					audit_msg(LOG_ERR, "error processing the <= operator for the %s field "
							"(value = %s) in event %i - this does not appear to be an integer number",
							phFieldChain->label, auparse_get_field_str(au), auparse_get_serial(au));
					audit_msg(LOG_ERR, "this is a problem in your %s config file", config->name);
					audit_msg(LOG_ERR, "you apparently have an eval option (#) on your %s filter and "
							"%s is not an integer", phFieldChain->label, phFieldChain->label);
				}
				if ( errcnt == 4 ) audit_msg(LOG_ERR, "Note: future processing of this error message is disabled. "
						"Restart auditd to re-enable");
				errcnt++;
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "the " DBGBOLDRED(%s) " field on the " DBGBOLDRED(%s)
						" record is not " DBGBOLDGREEN(AUPARSE_TYPE_UNCLASSIFIED) "\n",
						phFieldChain->label, phFieldChain->ParentTypeRecord->Name );
#endif	// DEBUG
				return ( -100 );
			}
			break;
		default:
			break;
	}

	return 0;
}

int regex_operator(struct ph_Chain * phFieldChain, auparse_state_t *au, ph_config_t *config) {
	int iret;
	const char * valString = NULL;
	char msgbuf[100];

#ifdef DEBUG
	if ( ( iret = checkOprArgs(phFieldChain, au) ) ) {
		audit_msg(LOG_ERR, "error processing the regex_operator for event %i", auparse_get_line_number(au));
		if(debug) WinFprintf(fp9, DBGBOLDRED(error processing the regex_operator) " for event %i\n", auparse_get_line_number(au));
		return ( iret );
	}
#endif	// DEBUG

	if ( phFieldChain->regexcomp == NULL ) {
#ifdef DEBUG
			audit_msg(LOG_ERR, "error processing the phFieldChain->regexcomp for event %i -- this is a program bug", auparse_get_line_number(au));
			if(debug) WinFprintf(fp9, DBGBOLDRED(error processing the phFieldChain->regexcomp) " for event %i -- NULL pointer\n", auparse_get_line_number(au));
#endif	// DEBUG
	}
	switch (phFieldChain->option) {
		case OPTINTERP:
			valString = auparse_interpret_field(au);
			break;
		case OPTNOINTERP:
			valString = auparse_get_field_str(au);
			break;
		default:
#ifdef DEBUG
			audit_msg(LOG_ERR, "error processing the regex_operator for event %i -- this is a program bug", auparse_get_line_number(au));
			if(debug) WinFprintf(fp9, DBGBOLDRED(error processing the regex_operator) " for event %i -- illegal option detected\n", auparse_get_line_number(au));
#endif	// DEBUG
			break;
	}
	    // apply regex
	iret = regexec(phFieldChain->regexcomp, valString, 0, NULL, 0);
	if (!iret) {
		return 1;
	} else if (iret == REG_NOMATCH) {
		return 0;
	} else {
		regerror(iret, phFieldChain->regexcomp, msgbuf, sizeof(msgbuf));
		audit_msg(LOG_ERR, "error processing the regex for event %i -- %s", auparse_get_line_number(au), msgbuf);
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDRED(error processing the regex) " for event %i -- " DBGBOLDRED(%s)  "\n", auparse_get_line_number(au), msgbuf);
#endif	// DEBUG

	}

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


void free_formatchain(ph_FormatChain_t * chain) {

	if ( chain == NULL ) return;
	if ( chain->next != NULL ) free_formatchain( chain->next );


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


ph_FilterChain_t * find_filterchain_end(ph_FilterChain_t * chain) {

	if ( chain->next == NULL ) {
		return (chain);
	} else {
		return (find_filterchain_end( chain->next ));
	}

}


ph_FormatChain_t * find_formatchain_end(ph_FormatChain_t * chain) {

	if ( chain->next == NULL ) {
		return (chain);
	} else {
		return (find_formatchain_end( chain->next ));
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
	free_formatchain( phKeyConfig->phFormatChain );
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
	freeTimerListChain(pphConfig->StatusTimerListHead);
	pphConfig->StatusTimerListHead = NULL;
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
	if ( chain->regexcomp != NULL ) regfree( chain->regexcomp );
	free(chain->regexcomp);
	chain->regexcomp = NULL;
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
	if ( chain->keyRateFilter != NULL ) free( chain->keyRateFilter );
	chain->keyRateFilter = NULL;
	if ( chain->defPolRateFilter != NULL ) free( chain->defPolRateFilter );
	chain->defPolRateFilter = NULL;
	free_filterchain(chain->phFilterChain);
	chain->phFilterChain = NULL;
	free_formatchain(chain->phFormatChain);
	chain->phFormatChain = NULL;

	free ( chain );
	chain = NULL;

	return;
}

void freeTimerListChain(timer_list_t * chain) {

	if ( chain == NULL ) return;
	if ( chain->next != NULL ) freeTimerListChain( chain->next );

//	stop timer
    timer_delete(chain->timer_id);

    free ( chain->name );
	free ( chain );
	chain = NULL;

	return;
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

timer_list_t * TailofTimerChain(timer_list_t * TimerChain) {

		if ( TimerChain->next == NULL ) {
			return (TimerChain);
		} else {
			return ( TailofTimerChain( TimerChain->next ) );
		}
}

static void freeargs( char **args, int nargs ) {
	if ( nargs > 0 ) {
		for (int i = 0;i < nargs; i++) {
			if ( args[i] != NULL ) free ( args[i] );
		}
	}
	if ( args != NULL ) free ( args );
	args = NULL;
	return;
}


static int checkVerbs( struct nv_pair *nv, int line, char * noun) {

#ifdef DEBUG
    if (nv->name == NULL || nv->name_len == 0 ) {
    	audit_msg(LOG_ERR, "name for %s is missing - line %d ... this is a program bug", noun, line);
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(name for %s is missing) " - line %d\n", noun, line);
    	return 1;
    }
    if ( strcmp (nv->name, noun) != 0 ) {
    	audit_msg(LOG_ERR, "name == %s but moun == %s - line %d ... this is a program bug", nv->name, noun, line);
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(name == %s but moun == %s) " - line %d\n", nv->name, noun, line);
    	return 2;
    }
#endif	// DEBUG
    if ( nv->option != OPTINTERP ) {
		audit_msg(LOG_ERR, "Error - syntax error on line %i in config file - ignoring line", line);
		audit_msg(LOG_ERR, "%s option makes no sense on a %s command", nv_lookup_option ( option_arg, nv->option ), noun);
		return 3;
    }
    if ( nv->operator != OPREQUAL ) {
		audit_msg(LOG_ERR, "Error - syntax error on line %i in config file - ignoring line", line);
		audit_msg(LOG_ERR, "%s operator makes no sense on a %s command", nv_lookup_option ( operator_arg, nv->operator ), noun);
		return 4;
    }
    if (nv->value == NULL || nv->value_len == 0 ) {
    	audit_msg(LOG_ERR, "%s value %s is missing - line %d", noun, nv->value, line);
    	return 5;
    }
    return 0;
}


int checkOprArgs(ph_Chain_t * phFieldChain, auparse_state_t *au) {

#ifdef DEBUG
    if (phFieldChain == NULL ) {
    	audit_msg(LOG_ERR, "phFieldChain in checkOprArgs is NULL... this is a program bug");
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(phFieldChain in checkOprArgs is NULL) "\n");
    	return -1;
    }
    if (phFieldChain->value == NULL ) {
    	audit_msg(LOG_ERR, "phFieldChain->value in checkOprArgs is NULL... this is a program bug");
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(phFieldChain->value in checkOprArgs is NULL) "\n");
    	return -2;
    }
    if (au == NULL ) {
    	audit_msg(LOG_ERR, "au in checkOprArgs is NULL... this is a program bug");
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(au in checkOprArgs is NULL) "\n");
    	return -3;
    }
    if ( auparse_get_type_name(au) == NULL ) {
    	audit_msg(LOG_ERR, "au in checkOprArgs is not valid... this is a program bug");
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(au in checkOprArgs is not valid) "\n");
    	return -4;
    }
#endif	// DEBUG

    return 0;
}


static long parse_time_with_suffix(const char *input_str, const char *noun, int line) {
    char *endptr;
    long value = strtol(input_str, &endptr, 10); // Parse the integer part

    if (endptr == input_str) { // No number found
    	audit_msg(LOG_ERR, "Error: No valid number found in optional %s time field on line %i in config file", noun, line);
#ifdef DEBUG
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(No valid number found in optional %s time field on line %i) "\n", noun, line);
#endif	// DEBUG
        return -1; // Indicate error
    }
    char suffix = tolower(*endptr); // Get the suffix and convert to lowercase
    switch (suffix) {
        case 's':
            return value; // Already in seconds
        case 'm':
            return value * 60; // Minutes to seconds
        case 'h':
            return value * 60 * 60; // Hours to seconds
        case 'd':
            return value * 24 * 60 * 60; // Days to seconds
        case '\0': // No suffix, assume seconds
            return value;
        default:
        	audit_msg(LOG_ERR, "Error: Invalid time unit suffix '%c' found in optional %s time field on line %i in config file", suffix, noun, line);
#ifdef DEBUG
        	if ( debug ) WinFprintf(fp9, DBGBOLDRED(Invalid time unit suffix '%c' found in optional %s time field on line %i) "\n", suffix, noun, line);
#endif	// DEBUG
            return -1; // Indicate error
    }
}


static long long parse_count_with_suffix(const char *str, int line) {
    char *endptr;
    long long value;
    // 1. Use strtoll to parse the initial numeric part
    errno = 0; // Reset errno before the call
    value = strtoll(str, &endptr, 10);
    // 2. Check for initial parsing errors (no digits found or out of range)
    if (endptr == str) {
    	audit_msg(LOG_ERR, "Error: count option field does not contain a valid number on line %i in config file", line);
#ifdef DEBUG
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(count option field does not contain a valid number on line %i) "\n", line);
#endif	// DEBUG
        return -1;
    }
    if ((value == LLONG_MAX || value == LLONG_MIN) && errno == ERANGE) {
    	audit_msg(LOG_ERR, "Error: the number in the count option field on line %i in config file is too big", line);
#ifdef DEBUG
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(number provided is outside the range of long long on line %i) "\n", line);
#endif	// DEBUG
        return -1;
    }
    // 3. Enforce positive integers requirement (strtoll handles the sign initially)
    if (value < 0) {
    	audit_msg(LOG_ERR, "Error: the number in the count option field on line %i in config file must be positive", line);
#ifdef DEBUG
    	if ( debug ) WinFprintf(fp9, DBGBOLDRED(Negative value in count option field on line %i) "\n", line);
#endif	// DEBUG
        return -1;
    }
    // 4. Check for an optional suffix
    if (*endptr != '\0') {
        char suffix = tolower((unsigned char)*endptr);
        long long multiplier = 1;

        switch (suffix) {
            case 'k':
                multiplier = 1024LL;
                break;
            case 'm':
                multiplier = 1024LL * 1024LL;
                break;
            case 'g':
                multiplier = 1024LL * 1024LL * 1024LL;
                break;
            default:
            	audit_msg(LOG_ERR, "Error: Invalid or unknown suffix '%c' on the count number on line %i in config file", *endptr, line);
#ifdef DEBUG
            	if ( debug ) WinFprintf(fp9, DBGBOLDRED(unknown suffix '%c' on the count number on line %i) "\n", *endptr, line);
#endif	// DEBUG
                return -1;
        }
        // Apply multiplier and check for overflow using built-in
        if (__builtin_mul_overflow(value, multiplier, &value)) {
        	audit_msg(LOG_ERR, "Error: Value overflowed when applying suffix multiplier to the count number on line %i in config file", line);
#ifdef DEBUG
        	if ( debug ) WinFprintf(fp9, DBGBOLDRED(Value overflowed in the count number on line %i) "\n", line);
#endif	// DEBUG
            return -1;
        }
        endptr++; // Move past the suffix
        // 5. Check that nothing follows the number AND the suffix (no trailing garbage)
        if (*endptr != '\0') {
        	audit_msg(LOG_ERR, "Error: Trailing characters detected after valid count number input on line %i in config file", line);
#ifdef DEBUG
        	if ( debug ) WinFprintf(fp9, DBGBOLDRED(Trailing characters detected in the count number on line %i) "\n", line);
#endif	// DEBUG
            return -1;
        }
    }

    // All checks passed
    return value;
}


static int parseRateOptions(struct nv_pair *nv, int line, unsigned long long int *count,
		unsigned long int *interval, unsigned long int *resetTime) {

	if ( nv->num_optional_args == 0 ) return 0;
	if ( nv->optional_args == NULL ) {
#ifdef DEBUG
        if ( debug ) WinFprintf(fp9, DBGBOLDRED(nv->optional_args == NULL) " while parsing line %i\n", line);
#endif	// DEBUG
		return 10;
	}
// parse count
	if ( nv->optional_args[0] == NULL ) {
#ifdef DEBUG
        if ( debug ) WinFprintf(fp9, DBGBOLDRED(nv->optional_args[0] == NULL) " while parsing line %i\n", line);
#endif	// DEBUG
		return 11;
	}
	if ( ( *count = parse_count_with_suffix(nv->optional_args[0], line) ) < 0 ) return 12;
// parse interval
	if ( nv->num_optional_args < 2 ) return 0;
	if ( nv->optional_args[1] == NULL ) {
#ifdef DEBUG
        if ( debug ) WinFprintf(fp9, DBGBOLDRED(nv->optional_args[1] == NULL) " while parsing line %i\n", line);
#endif	// DEBUG
		return 13;
	}
	if ( ( *interval = parse_time_with_suffix(nv->optional_args[1], "interval", line) ) < 0 ) return 14;
// parse reset time
	if ( nv->num_optional_args < 3 ) return 0;
	if ( nv->optional_args[2] == NULL ) {
#ifdef DEBUG
		if ( debug ) WinFprintf(fp9, DBGBOLDRED(nv->optional_args[2] == NULL) " while parsing line %i\n", line);
#endif	// DEBUG
		return 15;
	}
	if ( ( *resetTime = parse_time_with_suffix(nv->optional_args[2], "reset time", line) ) < 0 ) return 16;

	return 0;
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
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->defaultPolicy) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, nv_lookup_option ( default_arg,  KeyConfig->defaultPolicy ) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->defaultFormat) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, nv_lookup_option ( format_arg,  KeyConfig->defaultFormat ) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->currentPolicy) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, nv_lookup_option ( filter_arg,  KeyConfig->currentPolicy ) );
	WinFprintf(fp9, DBGBOLDGREEN(%s%s) DBGBOLDGREEN(->currentFormat) "; \t" DBGBOLDYELLOW(%s) "\n", t1, title, nv_lookup_option ( format_arg,  KeyConfig->currentFormat ) );
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->phFilterChain) );
	DumpFilterChainNext( tempstr2, tempstr,  KeyConfig->phFilterChain);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->phFormatChain) );
	DumpFormatChainNext( tempstr2, tempstr,  KeyConfig->phFormatChain);
	strcpy(tempstr, title);
	strcat(tempstr, DBGBOLDGREEN(->phFormatChain) );
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

void DumpFormatChainNext( char * t1, char * title, ph_FormatChain_t * Config){
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
