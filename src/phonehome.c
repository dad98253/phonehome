/*
 ============================================================================
 Name        : phonehome.c
 Author      : dad
 Version     :
 Copyright   : 2025
 Description : An auditd plugin to send an email warning without using a command
               script. This permits the simultanious use of email alerts and
               root command audit logging. (If you use a script to send email
               alerts and also audit log root commands, you will generate an
               infinite loop of audit messages and the kernel will be very
               unhappy - don't ask me how I know)
 ============================================================================
 */
/* based on audisp-syslog.c by Steve Grubb --
 * and the mail-file libESMTP example application by Brian Stafford
 * additional modifications were made by John Kuras
 *
 * Steve's original code is:
 * Copyright 2018 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * Brian's original code is:
 * Copyright (C) 2001,2002,2021  Brian Stafford <https://libesmtp.github.io/>
 *
 * Klous' original work is:
 * Copyright (C) 2007 International Business Machines  Corp.             *
 * All Rights Reserved.                                                  *
 *
 *
 * All modification or enhancements made by John Kuras are:
 * Copyright (c) John kuras 2025
 * All Rights Reserved.
 *
 * License for Steve's work states:
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * License for Bian's work states:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation; either version 2 of the License,
 *  or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * License for Klaus' work states is identical to Bian's with the exception
 *  that it does not reference the gnu url. instead it says:
 *  "if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston, MA  02111-1307, USA."
 *
 * License for all modifications made by John Kuras is:
 * DWTFYWWI (Do whatever you want with it)
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Brian Stafford <https://libesmtp.github.io/>
 *   Klaus Heinrich Kiwi <klausk@br.ibm.com>
 *   John Kuras <w7og@yahoo.com>
 *
 */
#include "config.h"
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <fcntl.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "common.h"
#include <auparse.h>
#ifdef DEBUG
#include "debug2.h"
#endif	// DEBUG
#define PHMAIN
#include "phonehome.h"
#include "ph-config.h"

static volatile int stop = 0;
static volatile int hup = 0;
static char *record = NULL;
static int sendmail = 0;
static int priority;
static int interpret = 0;
static auparse_state_t *au =NULL;


const char *capngerrors[] = {
        "not initialized",
        "CAPNG_SELECT_BOUNDS and failure to drop a bounding set capability",
        "CAPNG_SELECT_BOUNDS and failure to re-read bounding set",
        "CAPNG_SELECT_BOUNDS and process does not have CAP_SETPCAP",
        "CAPNG_SELECT_CAPS and failure in capset syscall",
        "CAPNG_SELECT_AMBIENT and process has no capabilities and failed clearing ambient capabilities",
        "CAPNG_SELECT_AMBIENT and process has capabilities and failed clearing ambient capabilities",
        "CAPNG_SELECT_AMBIENT and process has capabilities and failed setting an ambient capability",
        "Unable to acquire process capabilities to check if CAP_SETPCAP is set."
    };
const char * OuputDeviceType[] = {
        "FILEOUTPUT",
        "SERIALPORT",
        "CONSOLE",
        "TCPPORT",
        "BITBUCKET",
        "DEBUGWIN",
        "RAM"
};

#ifndef DEAFULTCONFIGPATH
static const char * DefaultConfigPath = "/etc/audit/phonehome.conf" ;	// protection from a bad config.h file...
#else	// DEAFULTCONFIGPATH
static const char * DefaultConfigPath = DEAFULTCONFIGPATH ;
#endif	// DEAFULTCONFIGPATH
static char * cpath;

static void term_handler( int sig );
static void hup_handler( int sig );
static void handle_read_event(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data);
static int init_ph(int argc, const char *argv[]);
static ph_Type_Chain_t * CheckTypeChain(ph_Type_Chain_t * phTypeChain, int type);
static ph_Chain_t * CheckFieldChain(ph_Chain_t * phFieldChain, const char * label);
extern int sendalert(ph_KeyConfig_t *tempKeyConf, auparse_state_t *au);
extern void audit_msg(int priority, const char *fmt, ...);
extern void NukemAll ( ph_config_t *pphConfig );
#ifdef DEBUG
extern int debug_init();
extern void debug_close();
extern int WinFprintf(FILE *hf, const char * fmt,...);
extern int OpenDebugDevice(FILE **hp);
extern int iDebugOutputDevice;
extern char * lpDebugServerName;
extern const struct nv_list auparse_types[];
extern char * nv_lookup_option ( const nv_list_t *nv, int myoption );
static void dump_whole_event(auparse_state_t *au);
static void dump_whole_record(auparse_state_t *au);
static void dump_fields_of_record(auparse_state_t *au);
#endif	// DEBUG
void restore_stdin();

int main(int argc, const char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;
//	struct timeval timeout;
	struct timespec timeout;
	int iret = 0;
	int retval = 0;

	// initialize the phonehome program
	if (init_ph(argc, argv)) return EXIT_FAILURE;
#ifdef DEBUG
	if(debug) {
		// set send audit_msg to send messages to syslog
		set_aumessage_mode(MSG_SYSLOG,DBG_YES);
	    lpDebugServerName = "grandma";
		debug_init();
		if ( OpenDebugDevice((FILE**)&fp9) == 0 ) {
			syslog(LOG_DEBUG, "OpenDebugDevice failed");
		} else {
			WinFprintf(fp9,"\33[1;32mDebug output device set to type %i\33[0m (%s)\n", iDebugOutputDevice,OuputDeviceType[iDebugOutputDevice]);
		}
	    WinFprintf(fp9, DBGBOLDGREEN(phonehome started) "\n");
	}
#endif	// DEBUG
    // Make sure stdin is in blocking, canonical mode
    restore_stdin();
	// Block SIGHUP and SIGTERM initially
	sigset_t block_mask, old_mask;
	iret = sigemptyset(&block_mask);
#ifdef DEBUG
	if(debug) {
		if (iret) WinFprintf(fp9, "sigemptyset " DBGBOLDRED(failed) " for block_mask with %s\n",strerror(errno));
	}
#endif	// DEBUG
	iret = sigaddset(&block_mask, SIGHUP);
#ifdef DEBUG
	if(debug) {
		if (iret) WinFprintf(fp9, "sigaddset " DBGBOLDRED(failed) " for SIGHUP with %s\n",strerror(errno));
	}
#endif	// DEBUG
	iret = sigaddset(&block_mask, SIGTERM);
#ifdef DEBUG
	if(debug) {
		if (iret) WinFprintf(fp9, "sigaddset " DBGBOLDRED(failed) " for SIGTERM with %s\n",strerror(errno));
	}
#endif	// DEBUG
	if (( iret = sigprocmask(SIG_BLOCK, &block_mask, &old_mask) ) == -1) {
#ifdef DEBUG
		if(debug) {
			WinFprintf(fp9, "sigprocmask " DBGBOLDRED(failed) " with %s\n",strerror(errno));
		}
#endif	// DEBUG
		return EXIT_FAILURE;
	}

	/* Register sighandlers */
	sa.sa_flags = 0;
	iret = sigemptyset(&sa.sa_mask);
#ifdef DEBUG
	if(debug) {
		if (iret) WinFprintf(fp9, "sigemptyset " DBGBOLDRED(failed) " for sa.sa_mask with %s\n",strerror(errno));
	}
#endif	// DEBUG
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	iret = sigaction(SIGTERM, &sa, NULL);
#ifdef DEBUG
	if(debug) {
		if (iret) {
			WinFprintf(fp9, "sigemptyset for SIGTERM " DBGBOLDRED(failed) " with %s\n",strerror(errno));
		} else {
			WinFprintf(fp9, "\"term_handler\" successfully set as handler for " DBGBOLDGREEN(SIGTERM) "\n");
		}
	}
#endif	// DEBUG
	sa.sa_handler = hup_handler;
	iret = sigaction(SIGHUP, &sa, NULL);
#ifdef DEBUG
	if(debug) {
		if (iret) {
			WinFprintf(fp9, "sigemptyset for SIGHUP " DBGBOLDRED(failed) " with %s\n",strerror(errno));
		} else {
			WinFprintf(fp9, "\"hup_handler\" successfully set as handler for " DBGBOLDGREEN(SIGHUP) "\n");
		}
	}
#endif	// DEBUG
#ifdef HAVE_LIBCAP_NG
	// Drop capabilities
	capng_clear(CAPNG_SELECT_BOTH);
    iret = capng_apply(CAPNG_SELECT_BOTH);
#ifdef DEBUG
    if(debug) {
    	if (iret) {
    		WinFprintf(fp9, "capng_apply " DBGBOLDRED(failed) " with %s\n",capngerrors[1-iret]);
    	} else {
    		WinFprintf(fp9, "capng_apply " DBGBOLDRED(CAPNG_SELECT_BOTH) "\n");
    	}
    }
#endif	// DEBUG
#endif
    // read the config file
	if ( load_phConfig(&phConfig, cpath) ) {
		return EXIT_FAILURE;
	}

	// start of main loop
	do {
		fd_set read_mask;
		retval = -1;
		int read_size = 1; // Set to 1 so it's not EOF

		// Load configuration
		if (hup) {
#ifdef DEBUG
			if(debug) {
				WinFprintf(fp9, DBGBOLDGREEN(reloading config file) "\n");
			}
#endif	// DEBUG
			NukemAll ( &phConfig );
			if ( load_phConfig(&phConfig, cpath) ) {
				return EXIT_FAILURE;
			}
			hup = 0;
			sendmail = 0;
		}
		// start of select loop
		do {
			FD_ZERO(&read_mask);
			FD_SET(0, &read_mask);
            sigset_t pselect_mask;
			if (auparse_feed_has_data(au)) {
				timeout.tv_sec = 5;  // set the time out Seconds
				timeout.tv_nsec = 0; // Nanoseconds
//				timeout.tv_usec = 0; // Microseconds
				// Prepare sigmask for pselect: temporarily unblock SIGTERM and SIGHUP
				iret = sigemptyset(&pselect_mask); // Empty mask means no signals are blocked during pselect
#ifdef DEBUG
				if(debug) {
					if (iret) WinFprintf(fp9, "sigemptyset " DBGBOLDRED(failed) " for pselect_mask with %s\n",strerror(errno));
					WinFprintf(fp9, "calling pselect...\n");
				}
#endif	// DEBUG
				// Waiting for data on pipe or child exit...
				//retval= select(1, &read_mask, NULL, NULL, &timeout);
				retval = pselect(1, &read_mask, NULL, NULL, &timeout, &pselect_mask);
			} else {
//				retval = pselect(1, &read_mask, NULL, NULL, NULL, &pselect_mask);
				retval = pselect(1, &read_mask, NULL, NULL, &timeout, &pselect_mask);
			}
			// If we timed out & have events, shake them loose
			if ( retval == 0 && auparse_feed_has_data(au) ) auparse_feed_age_events(au);
		} while (retval == -1 && errno == EINTR && !hup && !stop);
		// end of select loop
		if (retval == 0) {
#ifdef DEBUG
	    	if(debug) WinFprintf(fp9, DBGBOLDRED(Timeout) " occurred.\n");
#endif	// DEBUG
//		    continue;
		}
		/* Now the event loop */
		 if (!stop && !hup && retval > 0) {
#ifdef DEBUG
	    	if(debug) WinFprintf(fp9, "process an event\n");
#endif	// DEBUG
			if (FD_ISSET(0, &read_mask)) {
#ifdef DEBUG
		    	if(debug) WinFprintf(fp9, "FD_ISSET checks\n");
#endif	// DEBUG
				while ( ( read_size = read(0, tmp,  MAX_AUDIT_MESSAGE_LENGTH) ) > 0) {
#ifdef DEBUG
		    	if(debug) WinFprintf(fp9, DBGBOLDRED(%i) " " DBGBOLDYELLOW(bytes read from stdin) "\n", read_size);
#endif	// DEBUG
					auparse_feed(au, tmp, read_size);
				}
			}
		}
		if ( retval < 0 && errno != EINTR) {
			syslog(LOG_ERR, "select failed with %s", strerror(errno));
			break;
		}
		if (read_size == 0) {	// EOF
#ifdef DEBUG
	    	if(debug) WinFprintf(fp9, DBGBOLDRED(eof detected) "\n");
#endif	// DEBUG
			break;
		}
	} while (stop == 0);
	// end of main loop
#ifdef DEBUG
	if(debug) WinFprintf(fp9, DBGBOLDRED(stop detected... exiting) "\n");
#endif	// DEBUG
	// Restore original signal mask
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
#ifdef DEBUG
		if(debug) WinFprintf(fp9, "sigprocmask restore " DBGBOLDRED(failed) " with " DBGBOLDRED(%s) "\n",strerror(errno));
#endif	// DEBUG
	    return EXIT_FAILURE;
	}
	// Flush any accumulated events from queue
	auparse_flush_feed(au);
	auparse_destroy(au);
	sleep(1); // wait a second for auditd shutdown to catch up. Otherwise, it may restart us.
	syslog(LOG_INFO, "phonehome stoped");
	free(record);
	NukemAll ( &phConfig );
#ifdef DEBUG
	debug_close();
//	fclose(fd);
#endif	// DEBUG
	return EXIT_SUCCESS;
}


/*
 * SIGTERM handler
 */
static void term_handler( int sig )
{
        stop = 1;
//        syslog(LOG_INFO, "stopping phonehome");
}


/*
 * SIGHUP handler: re-read config
 */
static void hup_handler( int sig )
{
        hup = 1;
        syslog(LOG_INFO, "re-configuring phonehome");
}


static int init_ph(int argc, const char *argv[])
{

	priority = LOG_INFO;
    /*
      * the main program accepts a single (optional) argument:
      * it's configuration file (this is NOT the plugin configuration
      * usually located at /etc/audit/plugins.d)
      * We use the default (def_config_file) if no arguments are given
      */
	if (argc == 1) {
		cpath = (char *)DefaultConfigPath;
		syslog(LOG_WARNING, "No configuration file specified - using default (%s)", cpath);
	} else if (argc > 1) {
		cpath = (char *)argv[1];
		syslog(LOG_INFO, "Using configuration file: %s", cpath);
	}
#ifdef DEBUG
	if (argc > 2) {
		if ( strcmp((char *)argv[2], "debug") == 0 ) {
			debug = 1;
			syslog(LOG_INFO, "Debug option is enabled");
		}
	}
	if (argc > 3) {
#else	// DEBUG
	if (argc > 2) {
#endif	// DEBUG
		syslog(LOG_ERR, "Error - invalid number of parameters passed. Aborting");
		return 1;
	}

	interpret = 1;
	pid_t mypid = getpid();
	syslog(LOG_INFO, "plugin starting with pid=%d", mypid);
//	if (facility != LOG_USER) openlog("audispd", 0, facility);
	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
#ifdef DEBUG
		if(debug) {
			WinFprintf(fp9, DBGBOLDGREEN(phonehome audit plugin is exiting due to auparse init errors) "\n");
		}
#endif	// DEBUG
		audit_msg(LOG_ERR,"phonehome audit plugin is exiting due to auparse init errors at line %d in %s", __LINE__, __FILE__);
		return 2;
	}
	auparse_set_eoe_timeout(2);
	auparse_add_callback(au, handle_read_event, NULL, NULL);
	return 0;
}


void restore_stdin() {

    // Set file descriptor back to blocking
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
#ifdef DEBUG
    if(debug) {
    	if (flags == -1) WinFprintf(fp9, "fcntl " DBGBOLDRED(failed) " for F_GETFL with %s\n",strerror(errno));
    }
	int iret;
	iret =
#endif	// DEBUG
    fcntl(STDIN_FILENO, F_SETFL, flags |= O_NONBLOCK);
#ifdef DEBUG
    if(debug) {
    	if (iret == -1) WinFprintf(fp9, "fcntl " DBGBOLDRED(failed) " for F_SETFL with %s\n",strerror(errno));
    }
#endif	// DEBUG
}


#ifdef DEBUG
// This function dumps a whole event by iterating over records
static void dump_whole_event(auparse_state_t *au)
{
	WinFprintf(fp9, DBGBOLDCYAN(Dump whole event:) "\n");

	auparse_first_record(au);
	do {
		WinFprintf(fp9, DBGBOLDCYAN(%s) "\n", auparse_get_record_text(au));
		dump_fields_of_record(au);
	} while (auparse_next_record(au) > 0);
}


// This function dumps a whole record's text
static void dump_whole_record(auparse_state_t *au)
{
	WinFprintf(fp9, DBGBOLDCYAN(Dump whole record:) "\n");

	WinFprintf(fp9, DBGBOLDGREEN(%s) ": " DBGBOLDCYAN(%s) "\n", auparse_get_type_name(au), auparse_get_record_text(au));
}


// This function iterates through the fields of a record
// and print its name and raw value and interpreted value.
static void dump_fields_of_record(auparse_state_t *au)
{
	time_t EventTime;
	struct tm *timeinfo;
	char timestr[80];

	WinFprintf(fp9, DBGBOLDCYAN(Dump fields of record:) "\n");

	WinFprintf(fp9, DBGBOLDGREEN(record type) " " DBGBOLDRED(%d : %s) " has " DBGBOLDCYAN(%d) " fields\n", auparse_get_type(au), auparse_get_type_name(au), auparse_get_num_fields(au));
	WinFprintf(fp9, DBGBOLDBLACK(line=%d file=%s) "\n", auparse_get_line_number(au), auparse_get_filename(au) ? auparse_get_filename(au) : "stdin");
	const au_event_t *e = auparse_get_timestamp(au);
	if (e == NULL) {
		WinFprintf(fp9, DBGBOLDRED(Error getting time stamp - aborting) "\n");
		return;
	}
	/* Note that e->sec can be treated as time_t data if you want
	 * something a little more readable */
	EventTime = auparse_get_time(au);
	timeinfo = localtime(&EventTime);
	// Format the time into a string
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", timeinfo);
	WinFprintf(fp9, DBGBOLDRED(event time:) " " DBGBOLDGREEN(%s.%u:%lu) ", " DBGBOLDYELLOW(host) "=" DBGBOLDCYAN(%s) "\n", timestr, e->milli, e->serial, e->host ? e->host : "?");
	auparse_first_field(au);

	do {
		WinFprintf(fp9, DBGBOLDCYAN(field:) " " DBGBOLDGREEN(%s) "=" DBGBOLDYELLOW(%s) " (%s)\n",auparse_get_field_name(au),auparse_get_field_str(au),auparse_interpret_field(au));
	} while (auparse_next_field(au) > 0);
}
#endif	// DEBUG


// This function receives a single complete event at a time from the auparse library.
static void handle_read_event(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data)
{
	int type;
	int iret;
	int ftype;
	int i;
	int matches;
	int saved_stdin;
	unsigned long long int sum = 0;
	const char *fname;
	const char *fval;
	unsigned int numfields;
	ph_KeyConfig_t * tempKeyConf;
	ph_FilterChain_t * tempFilterChain;
	ph_Type_Chain_t * tempTypeChain;
	ph_Chain_t * TempFieldChain;

	if (cb_event_type != AUPARSE_CB_EVENT_READY) return;
#ifdef DEBUG
	if ( debug ) dump_whole_event(au);
#endif	// DEBUG
	// go to the first record in the event
	iret = auparse_first_record(au);
	if ( iret < 1 ) {
		// no records... bye!
//		auparse_destroy(au);
		return;
	}
	// AUDIT_EOE has no fields - drop it
	if ( ( numfields = auparse_get_num_fields(au) ) == 0) {
//		auparse_destroy(au);
		return;
	}
	// locate the event key field
	// for now we only will look in the first record - in audit.log, the key appears to
	// always be on the first record
	matches = 0;	// initialize the filter matches flag
	do {
		ftype = auparse_get_field_type(au);
#ifdef DEBUG
		fname = auparse_get_field_name(au);
#endif	// DEBUG
		// what if it has multiple key fields? We can't stop searching at the first key field we find...
		if ( ftype == AUPARSE_TYPE_ESCAPED_KEY ) {
			fval = auparse_interpret_field(au);
			sum = 0;
			for ( i = 0; i < strlen(fval); i++) {
				sum+= (unsigned char)( *(fval+i) );
			}
			i = sum & phConfig.hashmask;
#ifdef DEBUG
			if(debug) WinFprintf(fp9, DBGBOLDRED(key field found:) " " DBGBOLDGREEN(%s) " hashes to: " DBGBOLDCYAN(%i)   "\n", fval, i);
#endif	// DEBUG
			// Check for collision
#ifdef DEBUG
			if(debug) if (phKeyConfigs == NULL) WinFprintf(fp9, DBGBOLDRED(phKeyConfigs not initialized) " at %d in %s\n",__LINE__,__FILE__);
#endif	// DEBUG
			if ( phKeyConfigs[i] == NULL ) {
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "hash table location " DBGBOLDCYAN(%i) " is not occupied\n", i);
#endif	// DEBUG
				continue; // not in hash table
			}
			// hmmm... something is there, lets see if it's a match
			tempKeyConf = phKeyConfigs[i];
			while (1) {
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "check if " DBGBOLDGREEN(%s) " = " DBGBOLDMAGENTA(%s) "\n", fval, tempKeyConf->key);
#endif	// DEBUG
				if ( strcmp (tempKeyConf->key, fval) == 0 ) {
					matches = 1;	// signal that we found a match!!
					break;
				}
				if ( tempKeyConf->next == NULL ) break;
				tempKeyConf = tempKeyConf->next;
			}
			if ( matches ) {
#ifdef DEBUG
				if(debug) WinFprintf(fp9, DBGBOLDGREEN(key matches:) " " DBGBOLDRED(%s) "\n",fval);
#endif	// DEBUG
				break;
			}
		}	// note: there can be multiple keys specified for an event... we need to check all fields for keys
	} while ( auparse_next_field(au) > 0 );
	if ( !matches ) return; // no key field found
	matches = 0;	// initialize the filter matches flag
// key matches: check the filters for this key...
	if ( (tempFilterChain = tempKeyConf->phFilterChain) != NULL ) {
		// for each filter in the chain, do:
		do {
			// rewind to the first record
			auparse_first_record(au);
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "found a " DBGBOLDMAGENTA(%s %s) " for this key, get first record\n", tempFilterChain->label, tempFilterChain->value);
#endif	// DEBUG
			// check each record to see if it is in the filter's record type hash
			// hash the key
			do {
				type = auparse_get_type(au);
#ifdef DEBUG
				if(debug) WinFprintf(fp9, DBGBOLDYELLOW(record type:) " " DBGBOLDMAGENTA(%s) " (%i=%s)\n",auparse_get_type_name(au),auparse_get_type(au),nv_lookup_option(auparse_types,auparse_get_type(au)));
#endif	// DEBUG
				if ( tempFilterChain->TypeHashArray == NULL ) {
					// no TypeHashArray implies no types are filtered - the filter matches
					matches = 1;
#ifdef DEBUG
					if(debug) WinFprintf(fp9, "there is no Type Hash Array defined for this filter - all events " DBGBOLDGREEN(match) "\n");
#endif	// DEBUG
					break;
				}
				i = type % tempFilterChain->TypeHashSize;
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "this record type hashes into " DBGBOLDCYAN(%i) "\n", i);
#endif	// DEBUG
				tempTypeChain = tempFilterChain->TypeHashArray[i];
				if ( ( tempTypeChain = CheckTypeChain(tempTypeChain, type) ) == NULL ) {
#ifdef DEBUG
					if(debug) WinFprintf(fp9, "no match found for this record type in this filter - keep looking\n");
#endif	// DEBUG
					continue; // no match read the next record
				}
				// the type matches, tempTypeChain will now be pointing to the matching stuct
				tempTypeChain->Used = 1;	// mark it as used ("checked")
				// check for field matches
				if ( tempTypeChain->FieldHashArray == NULL ) {
#ifdef DEBUG
					if(debug) WinFprintf(fp9, "match found but no fields specified for this record type\n");
#endif	// DEBUG
					tempTypeChain->matches = matches = 1;
					continue; // no fields specified on this type record in our filter... it matches! - but continue checking records
				}
				auparse_first_field(au);
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "get first field\n");
#endif	// DEBUG
				do {
#ifdef DEBUG
					if(debug) WinFprintf(fp9, DBGBOLDCYAN(field:) " " DBGBOLDGREEN(%s) "=" DBGBOLDYELLOW(%s) " (%s)\n",auparse_get_field_name(au),auparse_get_field_str(au),auparse_interpret_field(au));
#endif	// DEBUG
					fname = auparse_get_field_name(au);
					sum = 0;
					for ( i = 0; i < strlen(fname); i++) {
						sum+= (unsigned char)( *(fname+i) );
					}
					i = sum % tempTypeChain->FieldHashSize;
#ifdef DEBUG
					if(debug) WinFprintf(fp9, "field: " DBGBOLDGREEN(%s) " hashes into " DBGBOLDCYAN(%i) " (%s)\n", fname, i);
#endif	// DEBUG
					// Check for collision
					TempFieldChain = tempTypeChain->FieldHashArray[i];
					if ( ( TempFieldChain = CheckFieldChain(TempFieldChain, fname) ) == NULL ) {
#ifdef DEBUG
						if(debug) WinFprintf(fp9, "no match found for this field name in our filter\n");
#endif	// DEBUG
						continue; // no match on label, check the next field
					}
					// check if the value matches ("*" matches everything)
					if ( ( strcmp(TempFieldChain->value, auparse_get_field_str(au)) == 0 ) || ( strcmp(TempFieldChain->value, "*") == 0 ) ) {
						// value matches - set the match bit in the type struct
						if ( tempTypeChain->MatchMaskArray == NULL ) {
#ifdef DEBUG
							if(debug) WinFprintf(fp9, DBGBOLDRED(the MatchMaskArray is missing - this is a programming bug) "\n");
#endif	// DEBUG
							return;
						}
						(tempTypeChain->FieldMaskArray[TempFieldChain->MatchMaskIndex]) = tempTypeChain->FieldMaskArray[TempFieldChain->MatchMaskIndex] | TempFieldChain->MatchMask;
#ifdef DEBUG
						if(debug) WinFprintf(fp9, "the value (" DBGBOLDGREEN(%s) ") matches\n", TempFieldChain->value);
#endif	// DEBUG
					}
					// check the next field
				} while ( auparse_next_field(au) > 0 );
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "get next record\n");
#endif	// DEBUG
			} while (auparse_next_record(au) > 0 );
////////////////////////////////////////////////////////////////////////////////
			// we're done with this section of the filter chain, let's see if we matched:
			matches = 1;
			// check first type in filter
			tempTypeChain = tempFilterChain->AllTypeChainHead;
			do {
				if ( tempTypeChain == NULL ) break;
				if ( !(tempTypeChain->Used) ) matches = 0;
				tempTypeChain->Used = 0;
				if ( ( tempTypeChain->FieldHashArray == NULL ) && !(tempTypeChain->matches) ) matches = 0;
				tempTypeChain->matches = 0;
				if ( tempTypeChain->numOfFieldChildren ) {
					for ( i=0; i<tempTypeChain->lengthOfMaskArray; i++) {
						if ( tempTypeChain->FieldMaskArray[i] ^ tempTypeChain->MatchMaskArray[i] ) matches = 0;
						tempTypeChain->FieldMaskArray[i] = 0ull;
					}
				}
			} while (( tempTypeChain = tempTypeChain->AllTypeChainNext ) != NULL);
			if ( matches ) {
				// process filter and skip remaining filters
#ifdef DEBUG
				if(debug) {
					WinFprintf(fp9, "filter " DBGBOLDGREEN(matches) "!\n");
					switch (tempFilterChain->PassOrReject) {
						case FILPASS:
							WinFprintf(fp9, DBGBOLDGREEN(%s) " event number %li !\n",tempFilterChain->value, auparse_get_serial(au));
							break;
						case FILREJECT:
							WinFprintf(fp9, DBGBOLDRED(%s) " event number %li !\n",tempFilterChain->value, auparse_get_serial(au));
							break;
						case FILEND:
							WinFprintf(fp9, DBGBOLDYELLOW(%s) " event number %li !\n",tempFilterChain->value, auparse_get_serial(au));
							break;
						default:
							WinFprintf(fp9, DBGBOLDRED(Error! Error! .. %s) " event number %li !\n",tempFilterChain->value, auparse_get_serial(au));
							break;
					}
				}
#endif	// DEBUG
				if ( tempFilterChain->PassOrReject == FILPASS ) {
					// somewhere deep in the bowls of the estmp library they close stdin and
					// thus destroy its file descriptor. This will cause our select call in
					// the main program to fail. The following is a kludge to get around this.
					auparse_first_record(au);
					saved_stdin = dup(STDIN_FILENO);
					// send the email alert
					sendalert(tempKeyConf, au);
					// restore the stdin descriptor
					dup2(saved_stdin, STDIN_FILENO);
					close(saved_stdin);
					// Now stdin should be restored
					audit_msg(LOG_INFO, "Event # \"%li\" precipitated a phone home message", auparse_get_serial(au));
				}
				break;
			}
#ifdef DEBUG
			if(debug) WinFprintf(fp9, "get next filter\n");
#endif	// DEBUG
		} while ( ( tempFilterChain = tempFilterChain->next ) != NULL );
#ifdef DEBUG
		if(debug) {
			if (matches) {
				WinFprintf(fp9, "The filter " DBGBOLDGREEN(matches) " for this event\n");
			} else {
				WinFprintf(fp9, "The filter " DBGBOLDRED(fails) " for this event\n");
			}
		}
#endif	// DEBUG
		if ( ( !matches || tempFilterChain->PassOrReject == FILEND ) && tempKeyConf->defaultPolicy == DEFPASS ) {	// check if should apply default policy
			auparse_first_record(au);
			saved_stdin = dup(STDIN_FILENO);
			// send the email alert
			sendalert(tempKeyConf, au);
			// restore the stdin descriptor
			dup2(saved_stdin, STDIN_FILENO);
			close(saved_stdin);
			// Now stdin should be restored
			audit_msg(LOG_INFO, "Event # \"%li\" precipitated a phone home message", auparse_get_serial(au));
		}
	} else {
#ifdef DEBUG
		if(debug) WinFprintf(fp9, DBGBOLDRED(no filter chain found for this key) "/n");
#endif	// DEBUG
	}

#ifdef DEBUG
	// Loop through the records in the event looking for one to process.
	int num=0;
	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		// Now branch based on what record type is found.
		switch (type) {
			case AUDIT_AVC:
				dump_fields_of_record(au);
				break;
			case AUDIT_SYSCALL:
				dump_whole_record(au);
				break;
			case AUDIT_CONFIG_CHANGE:
				dump_whole_record(au);
				break;
			case AUDIT_PROCTITLE:
				dump_whole_record(au);
				break;
			case AUDIT_CWD:
				dump_whole_record(au);
				break;
			case AUDIT_PATH:
				dump_whole_record(au);
				break;
			case AUDIT_USER_LOGIN:
				break;
			case AUDIT_ANOM_ABEND:
				break;
			case AUDIT_MAC_STATUS:
				dump_whole_event(au);
				break;
			default:
				if(debug) WinFprintf(fp9, DBGBOLDRED(unknown record type = %i) "/n",type);
				dump_whole_record(au);
				break;
		}
		num++;
	}
#endif	// DEBUG

	return;
}


ph_Type_Chain_t * CheckTypeChain(ph_Type_Chain_t * phTypeChain, int type) {

	if ( phTypeChain == NULL ) return (NULL);
	if (phTypeChain->Type == type) return phTypeChain;
	if ( phTypeChain->next == NULL ) {
		return (NULL);
	} else {
		return ( CheckTypeChain( phTypeChain->next , type) );
	}
}


ph_Chain_t * CheckFieldChain(ph_Chain_t * phFieldChain, const char * label) {

	if ( phFieldChain == NULL ) return (NULL);
	if ( strcmp (phFieldChain->label, label) == 0 ) return phFieldChain;
	if ( phFieldChain->next == NULL ) {
		return (NULL);
	} else {
		return ( CheckFieldChain( phFieldChain->next , label) );
	}
}
