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

/*
 * This is a program used for handling /proc/cryproc.
 * Basically, we open a file read-write and send whatever arrives
 * on stdin to /proc/cryproc and print the response on stdout.
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#define MAX 400

int main(void)
{
	char buf[MAX];
	char buf2[MAX];
	int read;
	int read2;
	int written;
	FILE *file = fopen("/proc/cryproc","r+b");
	if (!file) {
		fprintf(stderr,"Failed to open /proc/cryproc! Exiting.\n");
		return 1;
	}
	do {
		read = fread(buf,1,MAX,stdin);
		clearerr(file); /* ignore previous errors from read operations */
		written = fwrite(buf,1,read,file);
		fflush(file);
		if (ferror(file)) {
			fprintf(stderr,"Error: %s",strerror(errno));
			fclose(file);
			return 1;
		}
		do {
			read2 = fread(buf2,1,MAX,file);
			fwrite(buf2,1,read2,stdout);
		} while (read2 > 0);
	} while (read==MAX);
	fclose(file);

	return 0;
}

