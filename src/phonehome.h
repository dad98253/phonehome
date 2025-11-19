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
