/*
 * sendalert.c
 *
 *  Created on: Oct 3, 2025
 *      Author: dad
 */

#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>

#include <openssl/ssl.h>
#include <auth-client.h>
#include <libesmtp.h>
#include "sendto.h"
#include "ph-config.h"

#if !defined (__GNUC__) || __GNUC__ < 2
# define __attribute__(x)
#endif
#define unused      __attribute__((unused))

#define BUFLEN	8192

/* Global Data */

enum { TO = 10, CC, BCC, };

struct option longopts[] =
  {
    { "help", no_argument, NULL, '?', },
    { "version", no_argument, NULL, 'v', },
    { "host", required_argument, NULL, 'h', },
    { "monitor", no_argument, NULL, 'm', },
    { "crlf", no_argument, NULL, 'c', },
    { "notify", required_argument, NULL, 'n', },
    { "mdn", no_argument, NULL, 'd', },
    { "subject", required_argument, NULL, 's', },
    { "reverse-path", required_argument, NULL, 'f', },
    { "tls", no_argument, NULL, 't', },
    { "require-tls", no_argument, NULL, 'T', },
    { "noauth", no_argument, NULL, 1, },

    { "to", required_argument, NULL, TO, },
    { "cc", required_argument, NULL, CC, },
    { "bcc", required_argument, NULL, BCC, },

    { NULL, 0, NULL, 0, },
  };

char * mypassword = "";

void monitor_cb (const char *buf, int buflen, int writing, void *arg);
void print_recipient_status (smtp_recipient_t recipient,
			     const char *mailbox, void *arg);
int authinteract (auth_client_request_t request, char **result, int fields,
                  void *arg);
int tlsinteract (char *buf, int buflen, int rwflag, void *arg);
int handle_invalid_peer_certificate(long vfy_result);
void event_cb (smtp_session_t session, int event_no, void *arg, ...);
char * getpassjk ( char * prompt );

int sendalert (char * record) {
	  smtp_session_t session;
	  smtp_message_t message;
	  smtp_recipient_t recipient;
	  auth_context_t authctx;
	  const smtp_status_t *status;
	  struct sigaction sa;
	  char *host = NULL;
	  char *from = NULL;
	  char *subject = NULL;
//	  int nocrlf = 0;
	  int noauth = 0;
	  int to_cc_bcc = 0;
//	  char *file;
	  FILE *fp;
//	  int c;
	  char MyMessage[BUFLEN];

	  enum notify_flags notify = Notify_NOTSET;

	  /* This program sends only one message at a time.  Create an SMTP
	     session and add a message to it. */
	  auth_client_init ();
	  session = smtp_create_session ();
	  message = smtp_add_message (session);

	/* NB.  libESMTP sets timeouts as it progresses through the protocol.
	 In addition the remote server might close its socket on a timeout.
	 Consequently libESMTP may sometimes try to write to a socket with
	 no reader.  Ignore SIGPIPE, then the program doesn't get killed
	 if/when this happens. */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);

	/* Set the host running the SMTP server.  LibESMTP has a default port
	 number of 587, however this is not widely deployed so the port
	 is specified as 25 along with the default MTA host. */
	if ( phConfig.MTA != NULL) host = phConfig.MTA;
	smtp_set_server(session, host ? host : "localhost:25");

	/* Do what's needed at application level to use authentication.
	 */
	authctx = auth_create_context();
	auth_set_mechanism_flags(authctx, AUTH_PLUGIN_PLAIN, 0);
	auth_set_interact_cb(authctx, authinteract, NULL);

	/* Use our callback for X.509 certificate passwords.  If STARTTLS is
	 not in use or disabled in configure, the following is harmless. */
	smtp_starttls_set_password_cb(tlsinteract, NULL);
	smtp_set_eventcb(session, event_cb, NULL);

	/* Now tell libESMTP it can use the SMTP AUTH extension.
	 */
	if (!noauth)
		smtp_auth_set_context(session, authctx);

	/* Set the reverse path for the mail envelope.  (NULL is ok)
	 */
	smtp_set_reverse_path(message, from);

#if 0
	/* The message-id is OPTIONAL but SHOULD be present.  By default
	 libESMTP supplies one.  If this is not desirable, the following
	 prevents one making its way to the server.
	 N.B. It is not possible to prohibit REQUIRED headers.  Furthermore,
	 the submission server will probably add a Message-ID header,
	 so this cannot prevent the delivered message from containing
	 the message-id.  */
	smtp_set_header_option (message, "Message-Id", Hdr_PROHIBIT, 1);
#endif

	/* RFC 2822 doesn't require recipient headers but a To: header would
	 be nice to have if not present. */
	if (!to_cc_bcc)
		smtp_set_header(message, "To", NULL, NULL);

	/* Set the Subject: header.  For no reason, we want the supplied subject
	 to override any subject line in the message headers. */
	if (subject != NULL) {
		smtp_set_header(message, "Subject", subject);
		smtp_set_header_option(message, "Subject", Hdr_OVERRIDE, 1);
	}

	/* Open the message file and set the callback to read it.
	 */
//	file = argv[optind++];
//	if (strcmp(file, "-") == 0)
		fp = stdin;
//	else if ((fp = fopen(file, "r")) == NULL) {
//		fprintf(stderr, "can't open %s: %s\n", file, strerror(errno));
//		exit(1);
//	}
//	if (nocrlf)
		strcpy(MyMessage,"");
		strcat(MyMessage,"Subject: ");
		strcat(MyMessage,phConfig.LastSubject);
		strcat(MyMessage,"\r\n");
		strcat(MyMessage,"To: ");
		strcat(MyMessage,phConfig.LastMailTo);
		strcat(MyMessage,"\r\n");
		strcat(MyMessage,"From: root@firewall11\r\n");
		strcat(MyMessage,"\r\nWarning Will Robinson!!\r\n");
		// if we have adequate space left in the static buffer, append the audit record to the email text
		if ( strlen(record) < ( BUFLEN - strlen(MyMessage) - 10 ) ) {
			strcat(MyMessage,record);
			strcat(MyMessage,"\r\n");
		}
		smtp_set_messagecb(message, _smtp_message_str_cb, MyMessage);
//	else
//		smtp_set_message_fp(message, fp);

	/* Add remaining program arguments as message recipients.
	 */
//	while (optind < argc) {
		recipient = smtp_add_recipient(message, phConfig.LastMailTo);

		/* Recipient options set here */
		if (notify != Notify_NOTSET)
			smtp_dsn_set_notify(recipient, notify);
//	}

	/* Initiate a connection to the SMTP server and transfer the
	 message. */
	if (!smtp_start_session(session)) {
		char buf[128];

		fprintf(stderr, "SMTP server problem %s\n",
				smtp_strerror(smtp_errno(), buf, sizeof buf));
	} else {
		/* Report on the success or otherwise of the mail transfer.
		 */
		status = smtp_message_transfer_status(message);
		printf("%d %s", status->code,
				(status->text != NULL) ? status->text : "\n");
		smtp_enumerate_recipients(message, print_recipient_status, NULL);
	}

	/* Free resources consumed by the program.
	 */
	smtp_destroy_session(session);
	auth_destroy_context(authctx);
	fclose(fp);
	auth_client_exit();

	return EXIT_SUCCESS;
}


/* Callback to prnt the recipient status */
void print_recipient_status (smtp_recipient_t recipient,const char *mailbox, void *arg unused)
{
  const smtp_status_t *status;

  status = smtp_recipient_status (recipient);
  printf ("%s: %d %s", mailbox, status->code, status->text);
}


void
monitor_cb (const char *buf, int buflen, int writing, void *arg)
{
  FILE *fp = arg;

  if (writing == SMTP_CB_HEADERS)
    {
      fputs ("H: ", fp);
      fwrite (buf, 1, buflen, fp);
      return;
    }

 fputs (writing ? "C: " : "S: ", fp);
 fwrite (buf, 1, buflen, fp);
 if (buf[buflen - 1] != '\n')
   putc ('\n', fp);
}


/* Callback to request user/password info.  Not thread safe. */
int authinteract (auth_client_request_t request, char **result, int fields, void *arg unused)
{
  char prompt[64];
  static char resp[512];
  char *p, *rp;
  int i, n, tty;

  rp = resp;
  for (i = 0; i < fields; i++)
    {
      n = snprintf (prompt, sizeof prompt, "%s%s: ", request[i].prompt,
		    (request[i].flags & AUTH_CLEARTEXT) ? " (not encrypted)"
		    					: "");
      if (request[i].flags & AUTH_PASS)
	result[i] = getpassjk (prompt);
      else
	{
	  tty = open ("/dev/tty", O_RDWR);
	  if (write (tty, prompt, n) != n)
	    {
	    }
	  n = read (tty, rp, sizeof resp - (rp - resp));
	  close (tty);
	  p = rp + n;
	  while (isspace (p[-1]))
	    p--;
	  *p++ = '\0';
	  result[i] = rp;
	  rp = p;
	}
    }
  return 1;
}

int tlsinteract (char *buf, int buflen, int rwflag unused, void *arg unused)
{
  char *pw;
  int len;

  pw = getpassjk ("certificate password");
  len = strlen (pw);
  if (len + 1 > buflen)
    return 0;
  strcpy (buf, pw);
  return len;
}

int
handle_invalid_peer_certificate(long vfy_result)
{
  const char *k ="rare error";
  switch(vfy_result) {
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    k="X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT"; break;
  case X509_V_ERR_UNABLE_TO_GET_CRL:
    k="X509_V_ERR_UNABLE_TO_GET_CRL"; break;
  case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    k="X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE"; break;
  case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    k="X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE"; break;
  case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    k="X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY"; break;
  case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    k="X509_V_ERR_CERT_SIGNATURE_FAILURE"; break;
  case X509_V_ERR_CRL_SIGNATURE_FAILURE:
    k="X509_V_ERR_CRL_SIGNATURE_FAILURE"; break;
  case X509_V_ERR_CERT_NOT_YET_VALID:
    k="X509_V_ERR_CERT_NOT_YET_VALID"; break;
  case X509_V_ERR_CERT_HAS_EXPIRED:
    k="X509_V_ERR_CERT_HAS_EXPIRED"; break;
  case X509_V_ERR_CRL_NOT_YET_VALID:
    k="X509_V_ERR_CRL_NOT_YET_VALID"; break;
  case X509_V_ERR_CRL_HAS_EXPIRED:
    k="X509_V_ERR_CRL_HAS_EXPIRED"; break;
  case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    k="X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD"; break;
  case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    k="X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD"; break;
  case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    k="X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD"; break;
  case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    k="X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD"; break;
  case X509_V_ERR_OUT_OF_MEM:
    k="X509_V_ERR_OUT_OF_MEM"; break;
  case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    k="X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT"; break;
  case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    k="X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN"; break;
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    k="X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"; break;
  case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    k="X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE"; break;
  case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    k="X509_V_ERR_CERT_CHAIN_TOO_LONG"; break;
  case X509_V_ERR_CERT_REVOKED:
    k="X509_V_ERR_CERT_REVOKED"; break;
  case X509_V_ERR_INVALID_CA:
    k="X509_V_ERR_INVALID_CA"; break;
  case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    k="X509_V_ERR_PATH_LENGTH_EXCEEDED"; break;
  case X509_V_ERR_INVALID_PURPOSE:
    k="X509_V_ERR_INVALID_PURPOSE"; break;
  case X509_V_ERR_CERT_UNTRUSTED:
    k="X509_V_ERR_CERT_UNTRUSTED"; break;
  case X509_V_ERR_CERT_REJECTED:
    k="X509_V_ERR_CERT_REJECTED"; break;
  }
  printf("SMTP_EV_INVALID_PEER_CERTIFICATE: %ld: %s\n", vfy_result, k);
  return 1; /* Accept the problem */
}

void event_cb (smtp_session_t session unused, int event_no, void *arg,...)
{
  va_list alist;
  int *ok;

  va_start(alist, arg);
  switch(event_no) {
  case SMTP_EV_CONNECT:
  case SMTP_EV_MAILSTATUS:
  case SMTP_EV_RCPTSTATUS:
  case SMTP_EV_MESSAGEDATA:
  case SMTP_EV_MESSAGESENT:
  case SMTP_EV_DISCONNECT: break;
  case SMTP_EV_WEAK_CIPHER: {
    int bits;
    bits = va_arg(alist, long); ok = va_arg(alist, int*);
    printf("SMTP_EV_WEAK_CIPHER, bits=%d - accepted.\n", bits);
    *ok = 1; break;
  }
  case SMTP_EV_STARTTLS_OK:
    puts("SMTP_EV_STARTTLS_OK - TLS started here."); break;
  case SMTP_EV_INVALID_PEER_CERTIFICATE: {
    long vfy_result;
    vfy_result = va_arg(alist, long); ok = va_arg(alist, int*);
    *ok = handle_invalid_peer_certificate(vfy_result);
    break;
  }
  case SMTP_EV_NO_PEER_CERTIFICATE: {
    ok = va_arg(alist, int*);
    puts("SMTP_EV_NO_PEER_CERTIFICATE - accepted.");
    *ok = 1; break;
  }
  case SMTP_EV_WRONG_PEER_CERTIFICATE: {
    ok = va_arg(alist, int*);
    puts("SMTP_EV_WRONG_PEER_CERTIFICATE - accepted.");
    *ok = 1; break;
  }
  case SMTP_EV_NO_CLIENT_CERTIFICATE: {
    ok = va_arg(alist, int*);
    puts("SMTP_EV_NO_CLIENT_CERTIFICATE - accepted.");
    *ok = 1; break;
  }
  default:
    printf("Got event: %d - ignored.\n", event_no);
  }
  va_end(alist);
}

char * getpassjk ( char * prompt )
{
	return (mypassword);
}
