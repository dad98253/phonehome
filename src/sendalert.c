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
#include <gmime/gmime.h>
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

int sendalert(ph_KeyConfig_t *tempKeyConf, auparse_state_t *au) {
	GMimeMessage *message;
	GMimeMultipart *multipart;
	GMimeTextPart *text_part;
	GMimePart *attachment_part;
	GMimeStream *stream;
	GMimeStream *streamMem;
	GMimeDataWrapper *wrapper;
    GByteArray * message_string;
	const char *attachment_path = "/tmp/audit.tar.gz"; // Replace with your file path
	const char *attachment_mime_type = "application/x-tar"; // Adjust MIME type as needed (e.g., image/jpeg, application/pdf)
	smtp_session_t session;
	smtp_message_t smtpmessage;
	smtp_recipient_t recipient;
	auth_context_t authctx;
	const smtp_status_t *status;
	struct sigaction sa;
	char *host = NULL;
	char *from = NULL;
	int noauth = 0;
	const au_event_t *e;
	char MyMessage[BUFLEN];
	time_t EventTime;
	struct tm *timeinfo;
	char timestr[80];
	char tmpstr[60];

	enum notify_flags notify = Notify_NOTSET;
	// make sure that the archive does not exsist
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
//	create_tar_archive(attachment_path, "/var/log/audit");
	create_tar_archive(attachment_path, "/home/dad/workspace_test/testmime/Debug/testmime.c");

	/* Initialize the GMime library */
//	g_mime_init();

	/* 1. Create the top-level multipart/mixed container */
	multipart = g_mime_multipart_new_with_subtype("mixed");

	/* 2. Create the plain text body part */
	text_part = g_mime_text_part_new_with_subtype("plain");
	strcpy(MyMessage, "");
	auparse_first_record(au);
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
	do {
		// if we have adequate space left in the static buffer, append the audit record to the email text
		if (strlen((char *) auparse_get_record_text(au))
				< ( BUFLEN - strlen(MyMessage) - 10)) {
			strcat(MyMessage, (char *) auparse_get_record_text(au));
			strcat(MyMessage, "\r\n");
		}
	} while (auparse_next_record(au) > 0);
	g_mime_text_part_set_text(text_part, MyMessage);
	g_mime_object_set_header(GMIME_OBJECT(text_part), "Content-Disposition", "inline", NULL);

	/* 3. Create the attachment part from a file using GMime 3.0 specific functions */
	// A. Create an empty GMimePart object (default is application/octet-stream)
	attachment_part = g_mime_part_new();
	// B. Create a file stream to read the data from disk
	stream = g_mime_stream_fs_open(attachment_path, O_RDONLY, 0, NULL);
	if (!stream) {
		audit_msg(LOG_ERR,"Error opening file stream for: %s\n", attachment_path);
		g_object_unref(attachment_part);
		g_mime_shutdown();
		return EXIT_FAILURE;
	}

	// C. Wrap the stream in a GMimeDataWrapper.
	// The wrapper manages the stream, it takes ownership so we don't unref 'stream' manually yet.
	wrapper = g_mime_data_wrapper_new_with_stream(stream, GMIME_CONTENT_ENCODING_DEFAULT);

	// D. Set the Content of the part using the wrapper
	g_mime_part_set_content(attachment_part, wrapper);

	// E. Set the correct MIME Type (g_mime_part_new sets default, so we override it)
	g_mime_object_set_content_type(GMIME_OBJECT(attachment_part),
			g_mime_content_type_new(attachment_mime_type, NULL));

	// F. Set the Content-Disposition and filename
	g_mime_object_set_header(GMIME_OBJECT(attachment_part),
			"Content-Disposition", "attachment; filename=\"audit.tar.gz\"",
			NULL);

	// G. >>> SET THE CONTENT-TRANSFER-ENCODING TO BASE64 <<<
	g_mime_part_set_content_encoding(attachment_part,
			GMIME_CONTENT_ENCODING_BASE64);

	// We can unref the wrapper now, the attachment_part now holds the reference.
	g_object_unref(wrapper);

	/* 4. Add the body and the attachment to the multipart container */
	g_mime_multipart_add(multipart, GMIME_OBJECT(text_part));
	g_mime_multipart_add(multipart, GMIME_OBJECT(attachment_part));

	/* 5. Create the overall message and set headers */
	message = g_mime_message_new(TRUE);
	g_mime_message_set_subject(message, tempKeyConf->Subject, NULL);
	g_mime_message_add_mailbox(message, GMIME_ADDRESS_TYPE_SENDER, NULL, "sender@example.com");
	g_mime_message_add_mailbox(message, GMIME_ADDRESS_TYPE_SENDER, NULL, "recipient@example.com");

	// Set the constructed multipart as the body of the message
	g_mime_message_set_mime_part(message, GMIME_OBJECT(multipart));

	/* 6. Serialize the message to a string for sending (e.g., via SMTP or for debugging) */
	streamMem = g_mime_stream_mem_new();
	message_string = g_mime_stream_mem_get_byte_array(GMIME_STREAM_MEM(streamMem));
////	streamMem = g_mime_stream_mem_new_with_byte_array (message_string);
	g_mime_object_write_to_stream(GMIME_OBJECT(message), NULL, streamMem);

#ifdef DEBUG
		if(debug) {
			WinFprintf(fp9, DBGBOLDGREEN(--- Generated Email Message ---) "\n");
			WinFprintf(fp9, "%s\n", message_string->data);
			WinFprintf(fp9, DBGBOLDGREEN(--- End of Message ---) "\n");

			printf("--- Generated Email Message ---\n");
			printf("%s\n", message_string->data);
			printf("--- End of Message ---\n");
			testBase64((char *)attachment_path);
		}
#endif	// DEBUG

	// This program sends only one message at a time.  Create an SMTP
	// session and add a message to it.
	auth_client_init();
	session = smtp_create_session();
	if (session == NULL) {
		audit_msg(LOG_ERR,"Failed to create ESMTP session.");
		goto cleanup;
	}
	smtpmessage = smtp_add_message(session);

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
	if (phConfig.MTA != NULL) host = phConfig.MTA;
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
	smtp_set_reverse_path(smtpmessage, from);

#if 0
	/* The message-id is OPTIONAL but SHOULD be present.  By default
	 libESMTP supplies one.  If this is not desirable, the following
	 prevents one making its way to the server.
	 N.B. It is not possible to prohibit REQUIRED headers.  Furthermore,
	 the submission server will probably add a Message-ID header,
	 so this cannot prevent the delivered message from containing
	 the message-id.  */
	smtp_set_header_option (smtpmessage, "Message-Id", Hdr_PROHIBIT, 1);
#endif
	smtp_set_messagecb(smtpmessage, _smtp_message_str_cb, (char *) message_string->data);
	recipient = smtp_add_recipient(smtpmessage, phConfig.LastMailTo);

	/* Recipient options set here */
	if (notify != Notify_NOTSET) smtp_dsn_set_notify(recipient, notify);

	/* Initiate a connection to the SMTP server and transfer the
	 message. */
	if (!smtp_start_session(session)) {
		char buf[128];
		audit_msg(LOG_ERR,"SMTP server problem %s",
				smtp_strerror(smtp_errno(), buf, sizeof buf));
	} else {
		/* Report on the success or otherwise of the mail transfer.
		 */
		status = smtp_message_transfer_status(smtpmessage);
#ifdef DEBUG
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
	/* 8. Clean up GMime objects */
	g_mime_stream_flush (stream);
	g_mime_stream_flush (streamMem);

//	g_free(message_string);
//	guint8 * somebytes = g_byte_array_free(message_string, FALSE);
//	if(debug) {
//		WinFprintf(fp9, "g_byte_array_free returned %p\n", somebytes);
//	}
//	g_free(somebytes);

	// Clean up ESMTP session
	smtp_destroy_session(session);
	auth_destroy_context(authctx);
	auth_client_exit();

//	g_object_unref(message_string);
//	g_byte_array_unref(message_string);
	g_object_unref(attachment_part);
	g_object_unref(text_part);
	g_object_unref(multipart);
	g_object_unref(message);
	g_object_unref(stream);
	g_object_unref(streamMem);
//	g_mime_shutdown();

	return EXIT_SUCCESS;
}


/* Callback to prnt the recipient status */
void print_recipient_status (smtp_recipient_t recipient,const char *mailbox, void *arg unused)
{
	const smtp_status_t *status;

	status = smtp_recipient_status (recipient);
#ifdef DEBUG
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


/* Callback to request user/password info.  Not thread safe. */
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
	return 1; /* Accept the problem */
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
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK) {
			errmsg(archive_error_string(disk));
			errmsg("\n");
			exit(1);
		}
		archive_read_disk_descend(disk);
		r = archive_write_header(a, entry);
		if (r < ARCHIVE_OK) {
			errmsg(": ");
			errmsg(archive_error_string(a));
			needcr = 1;
		}
		if (r == ARCHIVE_FATAL)
			exit(1);
		if (r > ARCHIVE_FAILED) {
#if 0
			/* Ideally, we would be able to use
			 * the same code to copy a body from
			 * an archive_read_disk to an
			 * archive_write that we use for
			 * copying data from an archive_read
			 * to an archive_write_disk.
			 * Unfortunately, this doesn't quite
			 * work yet. */
			copy_data(disk, a);
#else
			/* For now, we use a simpler loop to copy data
			 * into the target archive. */
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


