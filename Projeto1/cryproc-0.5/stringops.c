#line 2 "stringops.c"
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

#include "stringops.h"

/* Append src to dest, copying at most max_src chars and making sure dest
 * doesn't get longer than max_dest.
 * Return the pointer to the trailing '\0' in modified dest.
 */
char *strcat_max(char *dest,const char *src,size_t max_src,size_t max_dest)
{
	int len;
	int max;
	len = strlen(dest);
	max = max_src < max_dest-len ? max_src : max_dest-len;
	strncat(dest,src,max);
	return dest+len+max;
}


/* Copy characters from source buffer (starting at *ptr) until a newline is
 * found or until the destination buffer is filled up. *ptr is modified to point
 * to the first character that hasn't been parsed yet. done_parsing is set to
 * indicate whether the string has been parsed completely (\n, \0 was found
 * in the buffer, or the maximum destination buffer capacity has been filled).
 * Return FALSE if destination buffer has been filled completely and no end of
 * line or string was found, TRUE otherwise.
 */
int read_till_newline(char *dest,const char *src,size_t max_src,size_t max_dest,
		const char **ptr,int *done_parsing)
{
	int result_len;
	int len;
	char c;
	*done_parsing = FALSE;
	/*DEBUG("dest=%p,src=%p,max_src=%i,max_dest=%i,*ptr-src=%i",dest,src,max_src,max_dest,*ptr-src);*/
	if (*ptr-src>=max_src)
		return TRUE;
	len = strlen(dest);
	while (*ptr-src<max_src && *ptr-src<max_dest-len
			&& **ptr!='\0' && **ptr!='\n')
		(*ptr)++;
	result_len = strcat_max(dest,src,*ptr-src,max_dest) - dest;
	/*DEBUG("result_len=%i",result_len);*/
	if (*ptr-src>=max_src) {
		return TRUE;
	}
	c = **ptr;
	if (c=='\0' || c=='\n') {
		*done_parsing = TRUE;
		(*ptr)++;
	}
	if (result_len>=max_dest && *ptr-src < max_src) {
		c = *((*ptr)++);
		if (c=='\n' || c=='\0') {
			*done_parsing = TRUE;
			return TRUE;
		} else {
			return FALSE;
		}
	}
	return TRUE;
}

/* Parse a string of hexadecimal digits and put their binary representation
 * in the same buffer.
 * Return -1 for error and the length in bytes of the resulting buffer
 * otherwise.
 */
int hex_string_to_bytes(char *str,int max_len)
{
	char *ptr;
	char *end;
	ptr = str;
	end = str+max_len;
	while (*str && end-str > 1) {
		int byte;
		byte = get_byte(str);
		if (byte==-1) {
			return -1;
		}
		*ptr = (char)byte;
		str+=2;
		ptr++;
	}
	return str-ptr;
}

/* Return the byte (0-255) value corresponding to two hex digits in str[0]
 * and str[1] or -1 if str doesn't start with two correct hex digits.
 */
int get_byte(const char *str)
{
	int v1 = hex_digit_val(str[0]);
	int v2 = hex_digit_val(str[1]);
	if (v1==-1 || v2==-1)
		return -1;
	else
		return 16*v1+v2;
}

/* Return the value corresponding to a single hexadecimal digit */
int hex_digit_val(char c)
{
	char cl = tolower(c);
	if (isxdigit(cl)) {
		if (isdigit(cl))
			return cl-'0';
		else
			return 10+cl-'a';
	} else {
		return -1;
	}
}

