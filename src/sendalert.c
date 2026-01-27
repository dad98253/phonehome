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
#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <openssl/ssl.h>
#include <auth-client.h>
#include <libesmtp.h>
#include <auparse.h>
#include "sendto.h"
#include "ph-config.h"

#include "libaudit.h"
#include "common.h"
#ifdef DEBUG
#include "debug2.h"
extern int WinFprintf(FILE *hf, const char * fmt,...);
#endif	// DEBUG
#include "ph-config.h"
#include "phonehome.h"

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
void print_recipient_status (smtp_recipient_t recipient, const char *mailbox, void *arg);
int authinteract (auth_client_request_t request, char **result, int fields, void *arg);
int tlsinteract (char *buf, int buflen, int rwflag, void *arg);
int handle_invalid_peer_certificate(long vfy_result);
void event_cb (smtp_session_t session, int event_no, void *arg, ...);
char * getpassjk ( char * prompt );
static void errmsg(const char *m);
static void msg(const char *m);
int create_tar_archive(const char *archive_name, const char *folder_path);
extern void audit_msg(int priority, const char *fmt, ...);
extern void testBase64 (char * attachment_path);
extern char *base64_encode_file(const char *filepath, size_t *output_len);
extern char * nv_lookup_option ( const nv_list_t *nv, int myoption );
extern ph_Type_Chain_t * CheckTypeChain(ph_Type_Chain_t * phTypeChain, int type);
extern ph_Chain_t * CheckFieldChain(ph_Chain_t * phFieldChain, const char * label);

extern const struct nv_list auparse_types[];

int sendalert(ph_KeyConfig_t *tempKeyConf, auparse_state_t *au, rfmtoverride_t fmtoverride, char * ExtraText ) {
// fmtoverride :
// RFMTOFF ==> no message text
// RFMTDEFAULT ==> default (controlled by format specified in config file
// RFMTFULLEVENT ==> ignore format & dump full event
// RFMTLOGFILES ==> like RFMTFULLEVENT but add attachment tar file

	const char *TarFileName = "audit.tar.gz";
	char *attachment_path = NULL;
//	const char *attachment_mime_type = "application/x-tar";           /////////////  should we be using this instead???
	ph_FormatChain_t *tempFormatChain = NULL;
	ph_Type_Chain_t * tempTypeChain = NULL;
	ph_Chain_t * TempFieldChain = NULL;
	smtp_session_t session;
	smtp_message_t smtpmessage;
	smtp_recipient_t recipient;
	auth_context_t authctx = NULL;
#ifdef DEBUG
	const smtp_status_t *status;
#endif	// DEBUG
	struct sigaction sa;
	char *host = NULL;
	char *from = NULL;
	int noauth = 0;
	const au_event_t *e;
	char *MyMessage = NULL;
	time_t EventTime;
	struct tm *timeinfo;
	char timestr[80];
	char tmpstr[60];
	char * b64string;
	size_t output_len = 0;
	int AttachLogs = 0;
	int FormatFullEvent = 0;
	int InterpretValues = 1;
	int type;
	int i;
	int matches;
	const char *fname;
	const char *fval;
	unsigned long long int sum = 0;

	enum notify_flags notify = Notify_NOTSET;

	// check if we are to include a copy of the audit log files
	// Note that we must check the entire format chain because the
	// flag could have been set anywhere in the chain
	if ( tempKeyConf->phFormatChain != NULL ) {
		tempFormatChain = tempKeyConf->phFormatChain;
		do {
			if ( tempFormatChain->AttachLogs ) {
				AttachLogs = 1;
				break;
			}
			tempFormatChain = tempFormatChain->next;
		} while (tempFormatChain != NULL);
		tempFormatChain = tempKeyConf->phFormatChain;	// reset the format chain back to its head
	} else {
		FormatFullEvent = 1;
	}
	if ( AttachLogs || fmtoverride == RFMTLOGFILES ) {
		// create the scratch file name
		attachment_path = strdup(phConfig.tmpDir);
		attachment_path = (char*)realloc(attachment_path, strlen(phConfig.tmpDir) + strlen(TarFileName) + 2 );
		strcat(attachment_path,TarFileName);
		// make sure that the archive does not exist
		if (remove(attachment_path) == 0) {
#ifdef DEBUG
			if(debug) {
				WinFprintf(fp9, "File " DBGBOLDGREEN(%s) " deleted successfully.\n", attachment_path);
			}
#endif	// DEBUG
		} else {
			audit_msg(LOG_ERR,"Error deleting '%s' archive file", attachment_path);
		}
	// create the archive file
		create_tar_archive(attachment_path, phConfig.logDir);
	//	create_tar_archive(attachment_path, "/home/dad/workspace_test/testmime/Debug/testmime.c");
	}

	// 1. Create the top-level multipart/mixed container
	MyMessage = (char*)calloc(BUFLEN, 1);
	strcpy(MyMessage, "");

	// 2. Create the plain text body part
	strcat(MyMessage,"Subject: ");
	strcat(MyMessage,tempKeyConf->Subject);
	strcat(MyMessage,"\r\n");
	strcat(MyMessage,"To: ");
	strcat(MyMessage,tempKeyConf->MailTo);
	strcat(MyMessage,"\r\n");
	strcat(MyMessage,"From: root@");
	strcat(MyMessage,myhostname);
	strcat(MyMessage,"\r\n");
	strcat(MyMessage,"MIME-Version: 1.0\r\n");
	strcat(MyMessage,"Content-Type: multipart/mixed; boundary=\"=-mdgBb2oZDbjIrIvgh75r\"\r\n");
	strcat(MyMessage,"\r\n");
	strcat(MyMessage,"\r\n");
	strcat(MyMessage,"--=-mdgBb2oZDbjIrIvgh75r\r\n");
	strcat(MyMessage,"Content-Type: text/plain; charset=us-ascii\r\n");
	strcat(MyMessage,"Content-Transfer-Encoding: 7bit\r\n");
	strcat(MyMessage,"Content-Disposition: inline\r\n");
	strcat(MyMessage,"\r\n");
	if ( ExtraText != NULL ) {
		strcat(MyMessage,ExtraText);
		strcat(MyMessage,"\r\n");
	}

	auparse_first_record(au);	// we should have to check for "no records" - (done before call to sendalert)
	sprintf(tmpstr, "%d", auparse_get_line_number(au));
	strcat(MyMessage, "line number, file name = ");
	strcat(MyMessage, tmpstr);
	strcat(MyMessage, ", ");
	strcat(MyMessage, auparse_get_filename(au) ? auparse_get_filename(au) : "stdin");
	strcat(MyMessage, "\r\n");
	e = auparse_get_timestamp(au);
	if (e != NULL) {
		// Note that e->sec can be treated as time_t data if you want something a little more readable
		EventTime = auparse_get_time(au);
		timeinfo = localtime(&EventTime);
		// Format the time into a string
		strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", timeinfo);
		strcat(MyMessage, "event time: ");
		strcat(MyMessage, timestr);
		strcat(MyMessage, ".");
		sprintf(tmpstr, "%d", e->milli);
		strcat(MyMessage, tmpstr);
		strcat(MyMessage, ":");
		sprintf(tmpstr, "%ld", e->serial);
		strcat(MyMessage, tmpstr);
		strcat(MyMessage, " host=");
		strcat(MyMessage, e->host ? e->host : "?");
		strcat(MyMessage, "\r\n");
	}
	if ( fmtoverride != RFMTOFF ) {
		// check if we use a custom format for the message
		// we should be on the first record
		// also, we do not need to look for the event key

		matches = 0;	// initialize the format matches flag
	// key matches: check the formats for this key...
		if ( (tempFormatChain = tempKeyConf->phFormatChain) != NULL ) {
			// for each format in the chain, do:
			do {
				if ( tempFormatChain->AttachLogs ) continue; // we already checked this above
				// rewind to the first record
				auparse_first_record(au);
#ifdef DEBUG
				if(debug) WinFprintf(fp9, "found " DBGBOLDMAGENTA(%s %s) ", get first record\n", tempFormatChain->label, tempFormatChain->value);
#endif	// DEBUG
				// check each record to see if it is in the format's record type hash
				// hash the key
				do {
					type = auparse_get_type(au);
#ifdef DEBUG
					if(debug) WinFprintf(fp9, DBGBOLDYELLOW(record type:) " " DBGBOLDMAGENTA(%s) " (%i=%s)\n",auparse_get_type_name(au),auparse_get_type(au),nv_lookup_option(auparse_types,auparse_get_type(au)));
#endif	// DEBUG
					if ( tempFormatChain->TypeHashArray == NULL ) {
						// no TypeHashArray implies no types are formatted - no formats match
#ifdef DEBUG
						if(debug) WinFprintf(fp9, "there is no Type Hash Array defined for this format - " DBGBOLDRED(no fields match) "\n");
#endif	// DEBUG
						break;
					}
					i = type % tempFormatChain->TypeHashSize;
#ifdef DEBUG
					if(debug) WinFprintf(fp9, "this record type hashes into " DBGBOLDCYAN(%i) "\n", i);
#endif	// DEBUG
					tempTypeChain = tempFormatChain->TypeHashArray[i];
					if ( ( tempTypeChain = CheckTypeChain(tempTypeChain, type) ) == NULL ) {
#ifdef DEBUG
						if(debug) WinFprintf(fp9, "no match found for this record type in this format - keep looking\n");
#endif	// DEBUG
						continue; // no match read the next record
					}
					// check for field matches
					if ( tempTypeChain->FieldHashArray == NULL ) {
#ifdef DEBUG
						if(debug) WinFprintf(fp9, "match found but no fields specified for this record type\n");
#endif	// DEBUG
						matches = 1;	// suppress full event dump
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
						if(debug) WinFprintf(fp9, "field: " DBGBOLDGREEN(%s) " hashes into " DBGBOLDCYAN(%i) "\n", fname, i);
#endif	// DEBUG
						// Check for collision
						TempFieldChain = tempTypeChain->FieldHashArray[i];
						if ( ( TempFieldChain = CheckFieldChain(TempFieldChain, fname) ) == NULL ) {
#ifdef DEBUG
							if(debug) WinFprintf(fp9, "no match found for this field name in our format\n");
#endif	// DEBUG
							continue; // no match on label, check the next field
						}
						// check if the value on the format field is blank ("" implies no alias)
						matches = 1;
						if ( ( strcmp(TempFieldChain->value, "" ) != 0 ) && ( strcmp(TempFieldChain->value, "*") != 0 ) ) fname = TempFieldChain->value;
						if ( InterpretValues ) {
							fval = auparse_interpret_field(au);
						} else {
							fval = auparse_get_field_str(au);
						}
						if ( fmtoverride == RFMTDEFAULT ) {
							if ( ( strlen(fval) + strlen(fname) ) < ( BUFLEN - strlen(MyMessage) - 10) ) {
								strcat(MyMessage, fname);
								strcat(MyMessage, " = ");
								strcat(MyMessage, fval);
								strcat(MyMessage, "\r\n");
							} else {
								audit_msg(LOG_ERR,"message buffer overflow on %s = %s .. using briefer aliases may help", fname, fval);
								return EXIT_FAILURE;
							}
						}
						if ( tempTypeChain->MatchMaskArray == NULL ) {
#ifdef DEBUG
							if(debug) WinFprintf(fp9, DBGBOLDRED(the MatchMaskArray is missing - this is a programming bug) "\n");
#endif	// DEBUG
							return EXIT_FAILURE;
						}
#ifdef DEBUG
						if(debug) WinFprintf(fp9, "wrote (" DBGBOLDGREEN(%s) " = " DBGBOLDGREEN(%s) " to message\n", fname, fval);
#endif	// DEBUG

						// check the next field
					} while ( auparse_next_field(au) > 0 );
#ifdef DEBUG
					if(debug) WinFprintf(fp9, "get next record\n");
#endif	// DEBUG
				} while (auparse_next_record(au) > 0 );
			} while ( ( tempFormatChain = tempFormatChain->next ) != NULL );
		} else {
			FormatFullEvent = 1;	// no format chain -> dump it all...
		}
		if ( !matches ) FormatFullEvent = 1;	// no formats matched -> dump it all...
			// check for if we are to include the full event report in the message
		if ( FormatFullEvent || fmtoverride == RFMTFULLEVENT || fmtoverride == RFMTLOGFILES ) {
			auparse_first_record(au);	// make sure we are still on the first record
			do {
				// if we have adequate space left in the static buffer, append the audit record to the email text
				if (strlen((char *) auparse_get_record_text(au))
						< ( BUFLEN - strlen(MyMessage) - 10)) {
					strcat(MyMessage, (char *) auparse_get_record_text(au));
					strcat(MyMessage, "\r\n");
				}
			} while (auparse_next_record(au) > 0);
		}
	}
	strcat(MyMessage, "\r\n");
	strcat(MyMessage, "\r\n");
	strcat(MyMessage,"--=-mdgBb2oZDbjIrIvgh75r\r\n");
	if ( ( AttachLogs && fmtoverride != RFMTOFF ) || fmtoverride == RFMTLOGFILES ) {
		// 3. Create the attachment part from the base64 string
		strcat(MyMessage, "Content-Type: application/octet-stream\r\n");
		strcat(MyMessage, "Content-Disposition: attachment; filename=audit.tar.gz\r\n");
		strcat(MyMessage, "Content-Transfer-Encoding: base64\r\n");
		strcat(MyMessage, "\r\n");
		strcat(MyMessage, "\r\n");

		b64string = base64_encode_file(attachment_path, &output_len);
		MyMessage = (char*)realloc(MyMessage, BUFLEN + output_len);
		strcat(MyMessage, b64string);
		free(b64string);
		b64string = NULL;
		free(attachment_path);
		attachment_path = NULL;

		strcat(MyMessage, "\r\n");
		strcat(MyMessage, "\r\n");
		strcat(MyMessage,"--=-mdgBb2oZDbjIrIvgh75r\r\n");
	}
#ifdef DEBUG
		if(debug) {
			WinFprintf(fp9, DBGBOLDGREEN(--- Generated Email Message ---) "\n");
#ifdef DEBUGMYMESSAGE
			WinFprintf(fp9, "%s\n", MyMessage);
#endif	// DEBUGMYMESSAGE
			WinFprintf(fp9, DBGBOLDGREEN(--- End of Message ---) "\n");

			printf("--- Generated Email Message ---\n");
#ifdef DEBUGMYMESSAGE
			printf("%s\n", MyMessage);
#endif	// DEBUGMYMESSAGE
			printf("--- End of Message ---\n");
		}
#endif	// DEBUG
	// Create an SMTP session and add a message to it.
	auth_client_init();
	session = smtp_create_session();
	if (session == NULL) {
		audit_msg(LOG_ERR,"Failed to create ESMTP session.");
		goto cleanup;
	}
	smtpmessage = smtp_add_message(session);
	//  libESMTP sets timeouts as it progresses through the protocol.
	// In addition the remote server might close its socket on a timeout.
	// Consequently libESMTP may sometimes try to write to a socket with
	// no reader.  Ignore SIGPIPE, then the program doesn't get killed
	// if/when this happens.
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);
	// Set the host running the SMTP server.  LibESMTP has a default port
	// number of 587, however this is not widely deployed so the port
	// is specified as 25 along with the default MTA host.
	if (phConfig.MTA != NULL) host = phConfig.MTA;
	smtp_set_server(session, host ? host : "localhost:25");
	// Do what's needed at application level to use authentication.
	authctx = auth_create_context();
	auth_set_mechanism_flags(authctx, AUTH_PLUGIN_PLAIN, 0);
	auth_set_interact_cb(authctx, authinteract, NULL);
	// Use our callback for X.509 certificate passwords.  If STARTTLS is
	// not in use or disabled in configure, the following is harmless.
	smtp_starttls_set_password_cb(tlsinteract, NULL);
	smtp_set_eventcb(session, event_cb, NULL);
	// Now tell libESMTP it can use the SMTP AUTH extension.
	if (!noauth)
		smtp_auth_set_context(session, authctx);
	// Set the reverse path for the mail envelope.  (NULL is ok)
	smtp_set_reverse_path(smtpmessage, from);
#if 0
	// The message-id is OPTIONAL but SHOULD be present.  By default
	// libESMTP supplies one.  If this is not desirable, the following
	// prevents one making its way to the server.
	// N.B. It is not possible to prohibit REQUIRED headers.  Furthermore,
	// the submission server will probably add a Message-ID header,
	// so this cannot prevent the delivered message from containing
	// the message-id.
	smtp_set_header_option (smtpmessage, "Message-Id", Hdr_PROHIBIT, 1);
#endif
	smtp_set_messagecb(smtpmessage, _smtp_message_str_cb, (char *) MyMessage);
	recipient = smtp_add_recipient(smtpmessage, phConfig.LastMailTo);
	// Recipient options set here
	if (notify != Notify_NOTSET) smtp_dsn_set_notify(recipient, notify);
	// Initiate a connection to the SMTP server and transfer the  message.
	if (!smtp_start_session(session)) {
		char buf[128];
		audit_msg(LOG_ERR,"SMTP server problem %s",
				smtp_strerror(smtp_errno(), buf, sizeof buf));
	} else {
		// Report on the success or otherwise of the mail transfer.
#ifdef DEBUG
		status = smtp_message_transfer_status(smtpmessage);
		if(debug) {
			WinFprintf(fp9, "smtp message transfer status code is " DBGBOLDYELLOW(%d)
					" status message : " DBGBOLDGREEN(%s) , status->code,
					(status->text != NULL) ? status->text : "\n");
		}
#endif	// DEBUG
		smtp_enumerate_recipients(smtpmessage, print_recipient_status, NULL);
	}
#ifdef DEBUG
	if(debug) {
		WinFprintf(fp9, "Message successfully sent using libesmtp!\n");
	}
#endif	// DEBUG

	// Free resources consumed by the program.
cleanup:
	if (MyMessage != NULL ) free(MyMessage);
	// Clean up ESMTP session
	smtp_destroy_session(session);
	if ( authctx != NULL ) auth_destroy_context(authctx);
	auth_client_exit();

	return EXIT_SUCCESS;
}


// Callback to prnt the recipient status
void print_recipient_status (smtp_recipient_t recipient,const char *mailbox, void *arg unused)
{
#ifdef DEBUG
	const smtp_status_t *status;

	status = smtp_recipient_status (recipient);
	if(debug) {
		WinFprintf(fp9, "print recipient status : " DBGBOLDGREEN(%s) " : " DBGBOLDYELLOW(%d)
				" " DBGBOLDRED(%s) , mailbox, status->code, status->text);
	}
#endif	// DEBUG
}


void monitor_cb (const char *buf, int buflen, int writing, void *arg)
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


// Callback to request user/password info.  Not thread safe.
int authinteract (auth_client_request_t request, char **result, int fields, void *arg unused)
{
	char prompt[64];
	static char resp[512];
	char *p, *rp;
	int i, n, tty;

	rp = resp;
	for (i = 0; i < fields; i++) {
		n = snprintf(prompt, sizeof prompt, "%s%s: ", request[i].prompt,
				(request[i].flags & AUTH_CLEARTEXT) ? " (not encrypted)" : "");
		if (request[i].flags & AUTH_PASS) {
			result[i] = getpassjk(prompt);
		} else {
			tty = open("/dev/tty", O_RDWR);
			if (write(tty, prompt, n) != n) {
			}
			n = read(tty, rp, sizeof resp - (rp - resp));
			close(tty);
			p = rp + n;
			while (isspace(p[-1]))
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

	pw = getpassjk("certificate password");
	len = strlen(pw);
	if (len + 1 > buflen) return 0;
	strcpy(buf, pw);
	return len;
}

int handle_invalid_peer_certificate(long vfy_result) {
	const char *k = "rare error";
	switch (vfy_result) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		k = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
		break;
	case X509_V_ERR_UNABLE_TO_GET_CRL:
		k = "X509_V_ERR_UNABLE_TO_GET_CRL";
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		k = "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		k = "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
		break;
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		k = "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
		break;
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		k = "X509_V_ERR_CERT_SIGNATURE_FAILURE";
		break;
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		k = "X509_V_ERR_CRL_SIGNATURE_FAILURE";
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
		k = "X509_V_ERR_CERT_NOT_YET_VALID";
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
		k = "X509_V_ERR_CERT_HAS_EXPIRED";
		break;
	case X509_V_ERR_CRL_NOT_YET_VALID:
		k = "X509_V_ERR_CRL_NOT_YET_VALID";
		break;
	case X509_V_ERR_CRL_HAS_EXPIRED:
		k = "X509_V_ERR_CRL_HAS_EXPIRED";
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		k = "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		k = "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
		break;
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		k = "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
		break;
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
		k = "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
		break;
	case X509_V_ERR_OUT_OF_MEM:
		k = "X509_V_ERR_OUT_OF_MEM";
		break;
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		k = "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
		break;
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		k = "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN";
		break;
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		k = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
		break;
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		k = "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
		break;
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		k = "X509_V_ERR_CERT_CHAIN_TOO_LONG";
		break;
	case X509_V_ERR_CERT_REVOKED:
		k = "X509_V_ERR_CERT_REVOKED";
		break;
	case X509_V_ERR_INVALID_CA:
		k = "X509_V_ERR_INVALID_CA";
		break;
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		k = "X509_V_ERR_PATH_LENGTH_EXCEEDED";
		break;
	case X509_V_ERR_INVALID_PURPOSE:
		k = "X509_V_ERR_INVALID_PURPOSE";
		break;
	case X509_V_ERR_CERT_UNTRUSTED:
		k = "X509_V_ERR_CERT_UNTRUSTED";
		break;
	case X509_V_ERR_CERT_REJECTED:
		k = "X509_V_ERR_CERT_REJECTED";
		break;
	}
	printf("SMTP_EV_INVALID_PEER_CERTIFICATE: %ld: %s\n", vfy_result, k);
	return 1; // Accept the problem
}

void event_cb(smtp_session_t session unused, int event_no, void *arg, ...) {
	va_list alist;
	int *ok;

	va_start(alist, arg);
	switch (event_no) {
	case SMTP_EV_CONNECT:
	case SMTP_EV_MAILSTATUS:
	case SMTP_EV_RCPTSTATUS:
	case SMTP_EV_MESSAGEDATA:
	case SMTP_EV_MESSAGESENT:
	case SMTP_EV_DISCONNECT:
		break;
	case SMTP_EV_WEAK_CIPHER: {
		int bits;
		bits = va_arg(alist, long);
		ok = va_arg(alist, int*);
		printf("SMTP_EV_WEAK_CIPHER, bits=%d - accepted.\n", bits);
		*ok = 1;
		break;
	}
	case SMTP_EV_STARTTLS_OK:
		puts("SMTP_EV_STARTTLS_OK - TLS started here.");
		break;
	case SMTP_EV_INVALID_PEER_CERTIFICATE: {
		long vfy_result;
		vfy_result = va_arg(alist, long);
		ok = va_arg(alist, int*);
		*ok = handle_invalid_peer_certificate(vfy_result);
		break;
	}
	case SMTP_EV_NO_PEER_CERTIFICATE: {
		ok = va_arg(alist, int*);
		puts("SMTP_EV_NO_PEER_CERTIFICATE - accepted.");
		*ok = 1;
		break;
	}
	case SMTP_EV_WRONG_PEER_CERTIFICATE: {
		ok = va_arg(alist, int*);
		puts("SMTP_EV_WRONG_PEER_CERTIFICATE - accepted.");
		*ok = 1;
		break;
	}
	case SMTP_EV_NO_CLIENT_CERTIFICATE: {
		ok = va_arg(alist, int*);
		puts("SMTP_EV_NO_CLIENT_CERTIFICATE - accepted.");
		*ok = 1;
		break;
	}
	default:
		printf("Got event: %d - ignored.\n", event_no);
	}
	va_end(alist);
}

char * getpassjk(char * prompt) {
	return (mypassword);
}

#if 0
// archive helper routine
static int copy_data(struct archive *ar, struct archive *aw) {
    int r;
    const void *buff;
    size_t size;
    la_int64_t offset;

    for (;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF)
            return (ARCHIVE_OK);
        if (r != ARCHIVE_OK)
            return (r);
        r = archive_write_data_block(aw, buff, size, offset);
        if (r != ARCHIVE_OK) {
        	audit_msg(LOG_ERR,"archive_write_data_block() error: %s", archive_error_string(aw));
            return (r);
        }
    }
}
#endif

static void errmsg(const char *m)
{
	if (m == NULL) {
		m = "Error: No error description provided.\n";
	}
	audit_msg(LOG_ERR,"%s", m);
}

static void msg(const char *m)
{
	audit_msg(LOG_INFO,"%s", m);
}

static char buff[16384];

int create_tar_archive(const char *archive_name, const char *folder_path) {
    struct archive *a;
    struct archive_entry *entry;

	ssize_t len;
	int fd;

    a = archive_write_new();
    archive_write_add_filter_gzip(a); // Optional: add gzip compression
    archive_write_set_format_ustar(a); // Or other formats like pax, gnutar
    archive_write_open_filename(a, archive_name);

	struct archive *disk = archive_read_disk_new();
	archive_read_disk_set_standard_lookup(disk);
	int r;
	r = archive_read_disk_open(disk, folder_path);
	if (r != ARCHIVE_OK) {
		errmsg(archive_error_string(disk));
		errmsg("\n");
		exit(1);
	}


    while (1) {
		int needcr = 0;

		entry = archive_entry_new();
		r = archive_read_next_header2(disk, entry);
		if (r == ARCHIVE_EOF) {
			archive_entry_free(entry);
			break;
		}
		if (r != ARCHIVE_OK) {
			errmsg(archive_error_string(disk));
			errmsg("\n");
			archive_entry_free(entry);
			exit(1);
		}
		archive_read_disk_descend(disk);
		r = archive_write_header(a, entry);
		if (r < ARCHIVE_OK) {
			errmsg(": ");
			errmsg(archive_error_string(a));
			needcr = 1;
		}
		if (r == ARCHIVE_FATAL) {
			archive_entry_free(entry);
			exit(1);
		}
		if (r > ARCHIVE_FAILED) {
#if 0
			// Ideally, we would be able to use the same code to copy a body from
			// an archive_read_disk to an archive_write that we use for
			// copying data from an archive_read to an archive_write_disk.
			// Unfortunately, this doesn't quite work yet.
			copy_data(disk, a);
#else
			// For now, we use a simpler loop to copy data into the target archive.
			fd = open(archive_entry_sourcepath(entry), O_RDONLY);
			len = read(fd, buff, sizeof(buff));
			while (len > 0) {
				archive_write_data(a, buff, len);
				len = read(fd, buff, sizeof(buff));
			}
			close(fd);
#endif
		}
		archive_entry_free(entry);
		if (needcr)
			msg("\n");
    }
	archive_read_close(disk);
	archive_read_free(disk);
	archive_write_close(a);
	archive_write_free(a);
    return 0;
}


