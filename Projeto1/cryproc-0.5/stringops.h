#line 2 "string_ops.h"
/*
 * Cryproc - Copyright (c) 2005 by Michal Kosmulski
 *
 * Cryproc is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Cryproc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _STRINGOPS_H_
#define _STRINGOPS_H_

#include <linux/string.h>
#include <linux/ctype.h>

#define TRUE 1
#define FALSE 0

int hex_digit_val(char c);
int get_byte(const char *str);
int hex_string_to_bytes(char *str,int max_len);
int read_till_newline(char *dest,const char *src,size_t max_src,
		size_t max_dest,const char **ptr,int *done_parsing);
char *strcat_max(char *dest,const char *src,size_t max_src,size_t max_dest);

#endif
