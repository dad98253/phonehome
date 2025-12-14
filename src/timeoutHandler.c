/*
 * timeoutHandler.c
 *
 *  Created on: Dec 8, 2025
 *      Author: dad, Google AI
 */



#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "ph-config.h"
#include "phonehome.h"
#ifdef DEBUG
#include "debug2.h"
extern int WinFprintf(FILE *hf, const char * fmt,...);
#endif	// DEBUG

extern void audit_msg(int priority, const char *fmt, ...);

#define errExit(msg) do { \
		audit_msg(LOG_ERR, "Error managing timer %s : %s", msg, strerror(errno)); \
		exit(EXIT_FAILURE); \
		} while (0)

#define SIG_TIMER SIGRTMIN + 1 // Use a real-time signal

#ifdef DEBUG
// Global variables to store timer IDs for comparison in the handler
timer_list_t timer1_data, timer2_data;
// Global count just for debug of how many times the handler runs vs events
volatile int handler_invocations = 0;
#endif	// DEBUG


// Signal handler function for timer expiration.
// It is called with SA_SIGINFO, allowing access to siginfo_t.
static void timeout_handler(int sig, siginfo_t *si, void *uc) {

	// Cast the sival_ptr back to our data structure
    timer_list_t *data = (timer_list_t *)si->si_value.sival_ptr;

    if (data == NULL) {
#ifdef DEBUG
    	if(debug) WinFprintf(fp9, DBGBOLDRED(NULL pointer to data in timer handler) "\n");
#endif	// DEBUG
        errExit("NULL pointer to data in timer handler -- this is a program bug!");
    }
    // un-mask the filter
    *(data->mask) = 0;

// --- Critical Logic Area ---

    if (data->should_restart) {
        struct itimerspec its;
        // set the next interval based on calculations
        its.it_value.tv_sec = data->parentRateTimerStruct->resetTime;
        its.it_value.tv_nsec = 9;
        its.it_interval.tv_sec = 0; // One shot
        its.it_interval.tv_nsec = 0;

        // Re-arm the specific timer using its ID from the context
        if (timer_settime(data->timer_id, 0, &its, NULL) == -1) {
#ifdef DEBUG
        	if(debug) WinFprintf(fp9, DBGBOLDRED(timer_settime failed in timer handler) "\n");
#endif	// DEBUG
        	errExit("timer reset failed in timer handler -- this might be a program bug!");
        }
    }
// --- End Critical Logic Area ---

#ifdef DEBUG
    handler_invocations++;
    if(debug) WinFprintf(fp9, DBGBOLDCYAN(--- Handler Invocation %d ---) "\n", handler_invocations);
    // Check which timer triggered the signal using the pointer passed in sival_ptr
	if(debug) WinFprintf(fp9, DBGBOLDGREEN(Timer (%s) expired!) "\n", data->name);
#endif	// DEBUG

	return;
}


// Helper function to create and arm a timer.
int create_timer(timer_list_t *td) {
    struct sigevent sev;
    struct sigaction sa;
	sigset_t	mask, old_mask;
	timer_t timer_id;

	// Make sure we haven't run out of timers
    if (SIG_TIMER > SIGRTMAX) {
#ifdef DEBUG
    	if(debug) WinFprintf(fp9, DBGBOLDRED(Ran out of real-time signals!) "\n");
#endif	// DEBUG
        errExit("Ran out of real-time signals!");
    }

    // Set up signal handler
    sa.sa_flags = SA_SIGINFO; // Required to get info in siginfo_t
    sa.sa_sigaction = timeout_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIG_TIMER, &sa, NULL) == -1) {
        errExit("sigaction");
    }

    // Block timer signal temporarily.
    sigemptyset(&mask);
    sigaddset(&mask, SIG_TIMER);
    if (sigprocmask(SIG_SETMASK, &mask, &old_mask) == -1)
        errExit("sigprocmask");

    // Set up sigevent structure
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIG_TIMER;
    // Pass a pointer to the timer data structure to the handler
    sev.sigev_value.sival_ptr = td;

    // Create the timer
    if (timer_create(CLOCK_REALTIME, &sev, &timer_id ) == -1) {
        errExit("timer_create");
    }
    td->timer_id = timer_id;

#ifdef DEBUG
	if(debug) WinFprintf(fp9, "Created timer " DBGBOLDGREEN(%s) " with ID "
			DBGBOLDCYAN(%p) "\n", td->name, (void*)td->timer_id);
#endif	// DEBUG

    // Unlock the timer signal, so that timer notification can be delivered.
    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1)
        errExit("sigprocmask");


    return 0;
}


void reset_timer(timer_t timerid, time_t interval_sec) {
    struct itimerspec its;

    // Set the time until the next expiration (the initial value)
    its.it_value.tv_sec = interval_sec;
    its.it_value.tv_nsec = 0;

    // Set the timer interval for subsequent expirations
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    // Arm (or re-arm) the timer with the new values.
    // This call resets the timer's current count back to the start.
    if (timer_settime(timerid, 0, &its, NULL) == -1) {
#ifdef DEBUG
    	if(debug) WinFprintf(fp9, DBGBOLDRED(timer_settime error in reset_timer) "\n");
#endif	// DEBUG
        errExit("timer_settime error");
    }

    return;
}



#ifdef TEST_TIMERS
int test_timers(void) {
    // Initialize timer data structures
    timer1_data.name = "FirstTimer";
    timer2_data.name = "SecondTimer";

    // Create two independent timers with different expiration times
    create_timer(&timer1_data);
    reset_timer(&timer1_data, 2); // Timer 1 expires in 2 seconds
    create_timer(&timer2_data);
    reset_timer(&timer2_data, 5); // Timer 2 expires in 5 seconds
#ifdef DEBUG
    	if(debug) WinFprintf(fp9, DBGBOLDRED(test_timers running... waiting for timers to expire) "\n");
#endif	// DEBUG

    // Keep the main process alive until timers fire (or we exit)
    // A real application might use sigwaitinfo() here to block efficiently
    for (;;) {
        sleep(10); // Sleep while waiting for signals
        break; // Exit after a while
    }

    // Clean up timers (optional, as the program exits shortly after)
    timer_delete(timer1_data.timer_id);
    timer_delete(timer2_data.timer_id);

#ifdef DEBUG
    	if(debug) WinFprintf(fp9, DBGBOLDGREEN(test_timers finished) "\n");
#endif	// DEBUG
    return EXIT_SUCCESS;
}
#endif	// TEST_TIMERS

