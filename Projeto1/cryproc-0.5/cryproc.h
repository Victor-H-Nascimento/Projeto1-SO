#line 2 "cryproc.h"
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

#ifndef _CRYPROC_H_
#define _CRYPROC_H_

#include <linux/kernel.h>
#include <linux/stat.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/highmem.h>
#include <asm/uaccess.h>
#include <asm/scatterlist.h>

#define TRUE 1
#define FALSE 0

#define KEY_MAX 64
#define SIZE_MAX 30
#define MAX_IVLEN 64
#define DEFLATE_BUFSIZE 65400

#define FORMATTED_MESSAGE(type,str,...) printk(type "%s:%i (%s) " str "\n", \
	__FILE__,__LINE__,__func__,##__VA_ARGS__)
	
#ifdef CRYPROC_DEBUG
#define DEBUG(str,...) FORMATTED_MESSAGE(KERN_DEBUG,str,##__VA_ARGS__)
#else
#define DEBUG(str,...)
#endif

#define ERROR(str,...) FORMATTED_MESSAGE(KERN_ERR,str,##__VA_ARGS__)
#define DEBUG_DATA(d) DEBUG("data: algo=%s,algo_in=%i," \
	"size=%s,size_in=%i,key_in=%i,failed=%i,bytes_done=%i,output_size=%i\n", \
	d->algo,d->algo_in,d->size,d->size_in,d->key_in,d->failed, \
	d->bytes_done,d->output_size)

#define return_rup(sem,val) { up_read(sem); return val; }
#define return_wup(sem,val) { up_write(sem); return val; }

#define proc_file_name "cryproc"

/* data stored in file->private_data, needed to preserve algorithms' state */
struct cryproc_data {
	struct crypto_tfm *tfm; /* tfm object used once the algorithm is running */
	struct rw_semaphore sem;
	
	char algo[CRYPTO_MAX_ALG_NAME]; /* algorithm name */
	int algo_in; /* has the algo field been read in completely? */

	/* The key field contains a string representation of the
	 * key at first and then the bytes of the key's binary
	 * representation. key[0] is the operation code (eg. crypt/decrypt) */
	char key[KEY_MAX+1];
	int key_length; /* key size(after converting to binary, not counting key[0]) */
	int key_in; /* has the key field been read in completely? */

	char size[SIZE_MAX]; /* data size as a string */
	int size_in; /* has the key field been read in completely? */
	int data_size; /* data size represented by the string in 'size' */
	
	int failed; /* has initializing the algorithm irrevocably failed? */
	int bytes_done; /* number of input data bytes processed */
	
	char *output; /* output of current algorithm's last round */
	int output_size; /* size of output */
	int total_prev_output; /* sum of previous output_size's in this run */
	char iv[MAX_IVLEN]; /* initialization vector, used in modes other than ECB */
	char tail[MAX_IVLEN]; /* last, incomplete block of data */
	int tail_len; /* amount of data stored in tail */
};

static ssize_t handle_write_buffer(const char *buf,size_t size,
		struct cryproc_data *data);

#endif
