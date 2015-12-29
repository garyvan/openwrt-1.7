  /* Copyright (C) 1996-2002, 2003, 2004, 2009 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/* All data returned by the network data base library are supplied in
   host order and returned in network order (suitable for use in
   system calls).  */

#ifndef	_NETDB_H
#define	_NETDB_H	1

#include <bits/netdb.h>

/* Description of data base entry for a single host.  */
struct hostent
{
  char *h_name;			/* Official name of host.  */
  char **h_aliases;		/* Alias list.  */
  int h_addrtype;		/* Host address type.  */
  int h_length;			/* Length of address.  */
  char **h_addr_list;		/* List of addresses from name server.  */
# define	h_addr	h_addr_list[0] /* Address, for backward compatibility.*/
};

/* Description of data base entry for a single service.  */
struct servent
{
  char *s_name;			/* Official service name.  */
  char **s_aliases;		/* Alias list.  */
  int s_port;			/* Port number.  */
  char *s_proto;		/* Protocol to use.  */
};

/* Description of data base entry for a single service.  */
struct protoent
{
  char *p_name;			/* Official protocol name.  */
  char **p_aliases;		/* Alias list.  */
  int p_proto;			/* Protocol number.  */
};
/* Return entry from network data base for network with NAME. */
#define getnetbyname(a) 0

/* Return entry from host data base for host with NAME.*/
/* extern struct hostent *gethostbyname (__const char *__name); */
#define gethostbyname(a) 0

/* Return entry from network data base for network with NAME and
   protocol PROTO. */
/* extern struct servent *getservbyname (__const char *__name,
				      __const char *__proto); */
#define getservbyname(...) 0

/* Return entry from protocol data base for network with NAME. */
/* extern struct protoent *getprotobyname (__const char *__name); */
#define getprotobyname(a) 0

/* Return entry from protocol data base which number is PROTO. */
/* extern struct protoent *getprotobynumber (int __proto);*/
#define getprotobynumber(a) 0
#endif	/* netdb.h */
