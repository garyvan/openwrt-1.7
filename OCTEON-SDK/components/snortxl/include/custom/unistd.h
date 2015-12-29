/* Copyright (C) 1991-2006, 2007, 2008, 2009 Free Software Foundation, Inc.
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

/*
 *	POSIX Standard: 2.10 Symbolic Constants		<unistd.h>
 */

#ifndef	_UNISTD_H
#define	_UNISTD_H	1

#ifdef CAV_OCT_SE

#define sleep(a) 0
#define getuid() 0
#define getgid() 0
#define setuid(a) 0
#define setgid(a) 0
#define execvp(a,b) 0
#define getcwd(a,b) 0
#define chdir(a) 0
#define getppid() 0
#define setsid() 0
#define dup(a) 0
#define chroot(a) 0
#define access(a,b) 0

#endif /* CAV_OCT_SE  */
#endif /* unistd.h  */
