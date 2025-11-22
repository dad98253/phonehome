/*
 * phonehome.h
 *
 *  Created on: Oct 31, 2025
 *      Author: dad
 */

#ifndef PHONEHOME_H_
#define PHONEHOME_H_

#ifndef PHMAIN
#define EXTERN		extern
#define INITIZERO
#define INITSZERO
#define INITIONE
#define INITINEGONE
#define INITBOOLFALSE
#define INITBOOLTRUE
#define INITNULL
#define INITJKNULL
#define INITBUFFERSIZE
#define INITDIRSIZE
#define INITVERNAMELEN
#define INITNULLSTRING
#else  // PHMAIN
#define EXTERN
#define INITIZERO	=0
#define INITSZERO	={0}
#define INITIONE	=1
#define INITINEGONE	=-1
#define INITBOOLFALSE	=false
#define INITBOOLTRUE	=true
#define INITNULL	=NULL
#define INITJKNULL  =JKNULL
#define INITBUFFERSIZE	=BUFFERSIZE
#define INITDIRSIZE		=DIRSIZE
#define INITVERNAMELEN  =VERNAMELEN
#define INITNULLSTRING  =""
#endif  // PHMAIN


EXTERN char * myhostname INITNULL;

#ifdef PHMAIN
const struct nv_list priority_ids[] =
{
		{ "LOG_DEBUG", LOG_DEBUG },
		{ "LOG_INFO", LOG_INFO },
		{ "LOG_NOTICE", LOG_NOTICE },
		{ "LOG_WARNING", LOG_WARNING },
		{ "LOG_ERR", LOG_ERR },
		{ "LOG_CRIT", LOG_CRIT },
		{ "LOG_ALERT", LOG_ALERT },
		{ "LOG_EMERG", LOG_EMERG },
		{ NULL, NOOPT }
};
const struct nv_list facility_ids[] =
{
		{ "LOG_LOCAL0", LOG_LOCAL0 },
		{ "LOG_LOCAL1", LOG_LOCAL1 },
		{ "LOG_LOCAL2", LOG_LOCAL2 },
		{ "LOG_LOCAL3", LOG_LOCAL3 },
		{ "LOG_LOCAL4", LOG_LOCAL4 },
		{ "LOG_LOCAL5", LOG_LOCAL5 },
		{ "LOG_LOCAL6", LOG_LOCAL6 },
		{ "LOG_LOCAL7", LOG_LOCAL7 },
		{ "LOG_AUTH", LOG_AUTH },
		{ "LOG_AUTHPRIV", LOG_AUTHPRIV },
		{ "LOG_DAEMON", LOG_DAEMON },
		{ "LOG_SYSLOG", LOG_SYSLOG },
		{ "LOG_USER", LOG_USER },
		{ NULL, NOOPT }
};
const struct nv_list option_ids[] =
{
		{ "debug", 1 },
		{ "interpret", 2 },
		{ "verbose", 3 },
		{ NULL, NOOPT }
};
#else	// PHMAIN
EXTERN const struct nv_list priority_ids[];
EXTERN const struct nv_list facility_ids[];
EXTERN const struct nv_list option_ids[];
#endif // PHMAIN

#undef EXTERN
#undef INITIZERO
#undef INITSZERO
#undef INITIONE
#undef INITINEGONE
#undef INITBOOLFALSE
#undef INITBOOLTRUE
#undef INITNULL
#undef INITJKNULL
#undef INITBUFFERSIZE
#undef INITDIRSIZE
#undef INITVERNAMELEN
#undef INITNULLSTRING
#endif /* PHONEHOME_H_ */
