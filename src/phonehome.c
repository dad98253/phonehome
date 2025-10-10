/*
 ============================================================================
 Name        : phonehome.c
 Author      : dad
 Version     :
 Copyright   : 2025
 Description : Auditd plugin to send an email warning without using a command
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
 * License for all modifications made by John Kuras is:
 * DWTFYWWI (Do whatever you want with it)
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Brian Stafford <https://libesmtp.github.io/>
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
#include "auparse.h"
#include "debug2.h"


static volatile int stop = 0;
static volatile int hup = 0;
static char *record = NULL;
static int sendmail = 0;
static int priority;
static int interpret = 0;
static char* mykeyval = "MailMe";
static int debug = 1;
FILE *fd; // debug File
FILE *fp9 = NULL;

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

static void term_handler( int sig );
static void hup_handler( int sig );
static void reload_config(void);
static int init_syslog(int argc, const char *argv[]);
static inline void write_syslog(char *s);
extern int sendalert (char * record);
extern int debug_init();
extern void debug_close();
void restore_stdin();

extern int WinFprintf(FILE *hf, const char * fmt,...);
extern int OpenDebugDevice(FILE **hp);
extern int iDebugOutputDevice;


int main(int argc, const char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;
//	struct timeval timeout;
	struct timespec timeout;
	int iret = 0;
	int retval = 0;
	// initialize the system log routine
	if (init_syslog(argc, argv)) return EXIT_FAILURE;
	if(debug) {
	    // Open debug file for writing, create if it doesn't exist, and truncate if it does
	    fd = fopen("/tmp/phdebug.txt", "w");
	    if (fd == NULL) {
	    	syslog(LOG_DEBUG, "debug file open failed");
	        return 1;
	    }
	    fprintf(fd,"phonehome started\n");
		debug_init();
		if ( OpenDebugDevice((FILE**)&fp9) == 0 ) {
			fprintf(fd,"OpenDebugDevice failed\n");
		} else {
			WinFprintf(fp9,"\33[1;32mDebug output device set to type %i\33[0m (%s)\n", iDebugOutputDevice,OuputDeviceType[iDebugOutputDevice]);
		}
	    WinFprintf(fp9,"phonehome started\n");
	}
    // Make sure stdin is in blocking, canonical mode
    restore_stdin();
	// Block SIGHUP and SIGTERM initially
	sigset_t block_mask, old_mask;
	iret = sigemptyset(&block_mask);
	if(debug) {
		if (iret) WinFprintf(fp9, "sigemptyset failed for block_mask with %s\n",strerror(errno));
	}
	iret = sigaddset(&block_mask, SIGHUP);
	if(debug) {
		if (iret) WinFprintf(fp9, "sigaddset failed for SIGHUP with %s\n",strerror(errno));
	}
	iret = sigaddset(&block_mask, SIGTERM);
	if(debug) {
		if (iret) WinFprintf(fp9, "sigaddset failed for SIGTERM with %s\n",strerror(errno));
	}
	if (( iret = sigprocmask(SIG_BLOCK, &block_mask, &old_mask) ) == -1) {
		if(debug) {
			WinFprintf(fp9, "sigprocmask failed with %s\n",strerror(errno));
		}
		exit(EXIT_FAILURE);
	}

	/* Register sighandlers */
	sa.sa_flags = 0;
	iret = sigemptyset(&sa.sa_mask);
	if(debug) {
		if (iret) WinFprintf(fp9, "sigemptyset failed for sa.sa_mask with %s\n",strerror(errno));
	}
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	iret = sigaction(SIGTERM, &sa, NULL);
	if(debug) {
		if (iret) WinFprintf(fp9, "sigemptyset for SIGTERM failed with %s\n",strerror(errno));
	}
	sa.sa_handler = hup_handler;
	iret = sigaction(SIGHUP, &sa, NULL);
	if(debug) {
		if (iret) WinFprintf(fp9, "sigemptyset for SIGHUP failed with %s\n",strerror(errno));
	}
#ifdef HAVE_LIBCAP_NG
	// Drop capabilities
//	capng_clear(CAPNG_SELECT_BOTH);
//    iret = capng_apply(CAPNG_SELECT_BOTH);
//    if(debug) {
//    	if (iret) WinFprintf(fp9, "capng_apply failed with %s\n",capngerrors[1-iret]);
//    }
#endif

	do {
		fd_set read_mask;
		retval = -1;

		/* Load configuration */
		if (hup) {
			reload_config();
		}
		do {
			FD_ZERO(&read_mask);
			FD_SET(0, &read_mask);
			timeout.tv_sec = 5;  // set the time out Seconds
			timeout.tv_nsec = 0; // Nanoseconds
//			timeout.tv_usec = 0; // Microseconds
            // Prepare sigmask for pselect: temporarily unblock SIGTERM and SIGHUP
            sigset_t pselect_mask;
            iret = sigemptyset(&pselect_mask); // Empty mask means no signals are blocked during pselect
    		if(debug) {
    			if (iret) WinFprintf(fp9, "sigemptyset failed for pselect_mask with %s\n",strerror(errno));
    			WinFprintf(fp9, "calling pselect...\n");
    		}
            // Waiting for data on pipe or child exit...
			//retval= select(1, &read_mask, NULL, NULL, &timeout);
    		retval = pselect(1, &read_mask, NULL, NULL, &timeout, &pselect_mask);
		} while (retval == -1 && errno == EINTR && !hup && !stop);
		if (retval == 0) {
	    	if(debug) {
	    		WinFprintf(fp9, "Timeout occurred.\n");
	    	}
//		    continue;
		}
		/* Now the event loop */
		 if (!stop && !hup && retval > 0) {
	    	if(debug) {
	    		WinFprintf(fp9, "process an event\n");
	    	}
			if (FD_ISSET(0, &read_mask)) {
		    	if(debug) {
		    		WinFprintf(fp9, "FD_ISSET checks\n");
		    	}
				do {
					if (audit_fgets(tmp, MAX_AUDIT_MESSAGE_LENGTH, 0) > 0) write_syslog(tmp);
				} while (audit_fgets_more(
						MAX_AUDIT_MESSAGE_LENGTH));
			}
		}
		if (audit_fgets_eof()) {
	    	if(debug) {
	    		WinFprintf(fp9, "eof detected\n");
	    	}
			break;
		}
	} while (stop == 0);
	if(debug) {
		WinFprintf(fp9, "stop detected... exiting\n");
	}
	// Restore original signal mask
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
		if(debug) {
			WinFprintf(fp9, "sigprocmask restore failed with %s\n",strerror(errno));
		}
	    exit(EXIT_FAILURE);
	}
	sleep(1); // wait a second for auditd shutdown to catch up. Otherwise, it may restart us.
	syslog(LOG_INFO, "phonehome stoped");
	free(record);
	debug_close();
	fclose(fd);
	return 0;
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

static void reload_config(void)
{
    if(debug) {
    	WinFprintf(fp9, "reloading config file\n");
    }
	hup = 0;
	sendmail = 0;
}

static int init_syslog(int argc, const char *argv[])
{
	int i, facility = LOG_USER;
	priority = LOG_INFO;

	for (i = 1; i < argc; i++) {
		if (argv[i]) {
			if (strcasecmp(argv[i], "LOG_DEBUG") == 0)
				priority = LOG_DEBUG;
			else if (strcasecmp(argv[i], "LOG_INFO") == 0)
				priority = LOG_INFO;
			else if (strcasecmp(argv[i], "LOG_NOTICE") == 0)
				priority = LOG_NOTICE;
			else if (strcasecmp(argv[i], "LOG_WARNING") == 0)
				priority = LOG_WARNING;
			else if (strcasecmp(argv[i], "LOG_ERR") == 0)
				priority = LOG_ERR;
			else if (strcasecmp(argv[i], "LOG_CRIT") == 0)
				priority = LOG_CRIT;
			else if (strcasecmp(argv[i], "LOG_ALERT") == 0)
				priority = LOG_ALERT;
			else if (strcasecmp(argv[i], "LOG_EMERG") == 0)
				priority = LOG_EMERG;
			else if (strcasecmp(argv[i], "LOG_LOCAL0") == 0)
				facility = LOG_LOCAL0;
			else if (strcasecmp(argv[i], "LOG_LOCAL1") == 0)
				facility = LOG_LOCAL1;
			else if (strcasecmp(argv[i], "LOG_LOCAL2") == 0)
				facility = LOG_LOCAL2;
			else if (strcasecmp(argv[i], "LOG_LOCAL3") == 0)
				facility = LOG_LOCAL3;
			else if (strcasecmp(argv[i], "LOG_LOCAL4") == 0)
				facility = LOG_LOCAL4;
			else if (strcasecmp(argv[i], "LOG_LOCAL5") == 0)
				facility = LOG_LOCAL5;
			else if (strcasecmp(argv[i], "LOG_LOCAL6") == 0)
				facility = LOG_LOCAL6;
			else if (strcasecmp(argv[i], "LOG_LOCAL7") == 0)
				facility = LOG_LOCAL7;
			else if (strcasecmp(argv[i], "LOG_AUTH") == 0)
				facility = LOG_AUTH;
			else if (strcasecmp(argv[i], "LOG_AUTHPRIV") == 0)
				facility = LOG_AUTHPRIV;
			else if (strcasecmp(argv[i], "LOG_DAEMON") == 0)
				facility = LOG_DAEMON;
			else if (strcasecmp(argv[i], "LOG_SYSLOG") == 0)
				facility = LOG_SYSLOG;
			else if (strcasecmp(argv[i], "LOG_USER") == 0)
				facility = LOG_USER;
			else if (strcasecmp(argv[i], "interpret") == 0)
				interpret = 1;
			else {
				syslog(LOG_ERR,
					"Unknown log priority/facility %s",
					argv[i]);
				return 1;
			}
		}
	}
	syslog(LOG_INFO,
		"phonehome plugin initialized with facility %d and priority %d",
		facility, priority);
	if (facility != LOG_USER)
		openlog("audispd", 0, facility);
	return 0;
}

static inline void write_syslog(char *s)
{
	if (interpret) {
		int rc, header = 0;
		char *mptr, tbuf[64];
    	if(debug) {
    		WinFprintf(fp9, "read and parse the record\n");
    	}
		// Setup record buffer
		if (record == NULL)
			record = malloc(MAX_AUDIT_MESSAGE_LENGTH);
		if (record == NULL)
			return;

		auparse_state_t *au = auparse_init(AUSOURCE_BUFFER, s);
		if (au == NULL)
			return;
		rc = auparse_first_record(au);

		// AUDIT_EOE has no fields - drop it
		if (auparse_get_num_fields(au) == 0) {
			auparse_destroy(au);
			return;
		}

		// Now iterate over the fields and print each one
		mptr = record;
		while (rc > 0 &&
		       ((mptr-record) < (MAX_AUDIT_MESSAGE_LENGTH-128))) {
			int ftype = auparse_get_field_type(au);
			const char *fname = auparse_get_field_name(au);
			const char *fval;
			//syslog(priority, "ftype,fname,fval = %i,\"%s\",\"%s\"", ftype, fname, fval);
			switch (ftype) {
				case AUPARSE_TYPE_ESCAPED_KEY:
					fval = auparse_interpret_field(au);
					//syslog(priority, "type %i found fval = %s", AUPARSE_TYPE_ESCAPED_KEY, fval);
					if ( strcmp(fval,mykeyval) == 0 ) sendmail = 1;
					break;
				case AUPARSE_TYPE_ESCAPED_FILE:
					fval = auparse_interpret_realpath(au);
					break;
				case AUPARSE_TYPE_SOCKADDR:
					fval =
					    auparse_interpret_sock_address(au);
					if (fval == NULL)
					    fval =
					      auparse_interpret_sock_family(au);
					break;
				default:
					fval = auparse_interpret_field(au);
					break;
			}

			mptr = stpcpy(mptr, fname ? fname : "?");
			mptr = stpcpy(mptr, "=");
			mptr = stpcpy(mptr, fval ? fval : "?");
			mptr = stpcpy(mptr, " ");
			rc = auparse_next_field(au);
			if (!header && fname && strcmp(fname, "type") == 0) {
				mptr = stpcpy(mptr, "msg=audit(");

				time_t t = auparse_get_time(au);
				struct tm *tv = localtime(&t);
				if (tv)
					strftime(tbuf, sizeof(tbuf),
								"%x %T", tv);
				else
					strcpy(tbuf, "?");
				mptr = stpcpy(mptr, tbuf);
				mptr = stpcpy(mptr, ") : ");
				header = 1;
			}
		}
		// Record is complete, dump it to syslog
		// syslog(priority, "%s", record);
		if (sendmail) {
			sendalert(record);
			syslog(priority, "warning email sent for msg = \"%s\"", record);
		}
		sendmail = 0;
		auparse_destroy(au);
	} else {
		char *c = strchr(s, AUDIT_INTERP_SEPARATOR);
		if (c)
			*c = ' ';
		syslog(priority, "%s", s);
	}
}

void restore_stdin() {
	int iret;
    // Restore default terminal attributes
/*    struct termios oldt;
    iret = tcgetattr(STDIN_FILENO, &oldt);
    if(debug) {
    	if (iret) WinFprintf(fp9, "tcgetattr failed for STDIN_FILENO with %s\n",strerror(errno));
    }
    oldt.c_lflag |= (ICANON | ECHO);
    iret = tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    if(debug) {
    	if (iret) WinFprintf(fp9, "tcsetattr failed for STDIN_FILENO with %s\n",strerror(errno));
    } */
    // Set file descriptor back to blocking
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if(debug) {
    	if (flags == -1) WinFprintf(fp9, "fcntl failed for F_GETFL with %s\n",strerror(errno));
    }
    iret = fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);
    if(debug) {
    	if (iret == -1) WinFprintf(fp9, "fcntl failed for F_SETFL with %s\n",strerror(errno));
    }
}


