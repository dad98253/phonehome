#ifdef DEBUG
#include "config.h"

/******************************************************************************\
* Simple TCP/UDP client using Winsock 1.1
* 
*       This is a part of the Microsoft Source Code Samples.
*       Copyright 1996-1997 Microsoft Corporation.
*       All rights reserved.
*       This source code is only intended as a supplement to
*       Microsoft Development Tools and/or WinHelp documentation.
*       See these sources for detailed information regarding the
*       Microsoft samples programs.
\******************************************************************************/
//
// Note: The vast majority of this file is new code written by John Kuras
//       However, at its core (the series of Winsocks calls opening and calling
//       an ip port on Windows) is based on the above mentioned sample code.
//       Therefore, the above copyright notice has been included to cover any
//       of the original code that may still exsist here. If Microsoft lawyers
//       wish to identify specific offending lines of code, I would be very happy
//       to change them.
//       All of the unix code is based on open source (non-copyrighted) samples
//       available online.
//
// All new code (excluding anything written by Microsoft) is:
//
//		Copyright (c) 2011-2023, John Kuras
//
//		See included LICENSE file for lisensing information.
//


#ifdef WINDOZE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define DEFAULT_PORT 5001
#ifdef WINDOZE
#define DEFAULT_PROTO SOCK_DGRAM // UDP
#else
#define DEFAULT_PROTO 2
#define SOCKET_ERROR	-1
#endif
int OpenTCPport(void);
int IPSend(char * data, int MaxDataSize);
int ClosePort(void);

struct sockaddr_in server;
struct hostent *hp;
#ifdef WINDOZE
WSADATA wsaData;
SOCKET  conn_socket;
#else
int  conn_socket;
extern int h_errno;
#endif
unsigned int addr;
char *server_name;
unsigned short port = DEFAULT_PORT;
int socket_type = DEFAULT_PROTO;

char * lpDebugServerName = NULL;
int iDebugServerPort = 0;

int OpenTCPport(void) {
	char *default_server_name = (char*)"localhost";
	if ( lpDebugServerName == NULL ) {
		server_name = default_server_name;
	} else {
		server_name = lpDebugServerName;
	}
#ifdef DEBUGOPENTCPPORT
	fprintf(stderr,"opening server %s for port %i\n",server_name,iDebugServerPort);
#endif	// DEBUGOPENTCPPORT
#ifdef WINDOZE
	if (WSAStartup(0x202,&wsaData) == SOCKET_ERROR) {
		fprintf(stderr,"WSAStartup failed with error %d\n",WSAGetLastError());
		WSACleanup();
		return 0;
	}
#endif
	if (isalpha(server_name[0])) {   /* server address is a name */
		hp = gethostbyname(server_name);
	}
	else  { /* Convert nnn.nnn address to a usable one */
		addr = inet_addr(server_name);
		hp = gethostbyaddr((char *)&addr,4,AF_INET);
	}
	if (hp == NULL ) {
#ifdef WINDOZE
#ifdef DEBUGOPENTCPPORT
		fprintf(stderr,"Client: Cannot resolve address [%s] to hostname: Error %d\n",
			server_name,WSAGetLastError());
#endif	// DEBUGOPENTCPPORT
#else	// WINDOZE
#ifdef DEBUGOPENTCPPORT
		int errsv = errno;
		int herrsv = h_errno;
		fprintf(stderr,"Client: Cannot resolve address [%s]: Error %d, h_err = %i\n",
			server_name,errsv,herrsv);
		fprintf(stderr,"%s\n", hstrerror(h_errno));
		if (h_errno == HOST_NOT_FOUND) fprintf(stderr,"Note: on linux, ip addresses must have valid RDNS entries\n");
#endif	// DEBUGOPENTCPPORT
#endif	// WINDOZE
//		return 0;	////////////   ???? why is this commented out on linux??
	}

	//
	// Copy the resolved information into the sockaddr_in structure
	//  iDebugServerPort
	memset(&server,0,sizeof(server));
	if ( hp == NULL ){
		server.sin_addr.s_addr = inet_addr(server_name);
		server.sin_family = AF_INET;
	} else {
		memcpy(&(server.sin_addr),hp->h_addr,hp->h_length);
		server.sin_family = hp->h_addrtype;
	}
	if ( iDebugServerPort != 0 ) port = iDebugServerPort;
	server.sin_port = htons(port);

	conn_socket = socket(AF_INET,socket_type,0); /* Open a socket */
	if (conn_socket <0 ) {
#ifdef WINDOZE
		fprintf(stderr,"Client: Error Opening socket: Error %d\n",
			WSAGetLastError());
		WSACleanup();
#else
		int errsv = errno;
		fprintf(stderr,"Client: Error Opening socket: Error %d\n",
				errsv);
#endif
		return 0;
	}

	//
	// Notice that nothing in this code is specific to whether we 
	// are using UDP or TCP.
	// We achieve this by using a simple trick.
	//    When connect() is called on a datagram socket, it does not 
	//    actually establish the connection as a stream (TCP) socket
	//    would. Instead, TCP/IP establishes the remote half of the
	//    ( LocalIPAddress, LocalPort, RemoteIP, RemotePort) mapping.
	//    This enables us to use send() and recv() on datagram sockets,
	//    instead of recvfrom() and sendto()

#ifdef DEBUGOPENTCPPORT
	if ( hp != NULL ) {
		fprintf(stderr,"Client connecting to: %s\n",hp->h_name);
	} else {
		fprintf(stderr,"Client connecting to: %s\n",server_name);
	}
#endif
	if (connect(conn_socket,(struct sockaddr*)&server,sizeof(server))
		== SOCKET_ERROR) {
#ifdef WINDOZE
		fprintf(stderr,"connect() failed: %d\n",WSAGetLastError());
		WSACleanup();
#else
		int errsv = errno;
		fprintf(stderr,"connect() failed: %d\n",errsv);
#endif
		return 0;
	}

	return 1;
}

int IPSend(char * Buffer, int MaxDataSize) {
	int retval = 0;
		retval = send(conn_socket,Buffer,strlen(Buffer)+1,0);
		if (retval == SOCKET_ERROR) {
#ifdef WINDOZE
			fprintf(stderr,"send() failed: error %d\n",WSAGetLastError());
			WSACleanup();
#else
		int errsv = errno;
		fprintf(stderr,"send() failed: error %d\n",errsv);
#endif
			return -1;
		}
//		printf("Sent Data [%s]\n",Buffer);
	return 0;
}

int ClosePort(void) {
#ifdef WINDOZE
	closesocket(conn_socket);
	WSACleanup();
#else
	close(conn_socket);
#endif
	return 1;
}

#endif	// DEBUG
