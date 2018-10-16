#line 2 "file.c"
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

#include "cryproc.h"
#include "stringops.h"

static int cryproc_open (struct inode *i, struct file *f)
{
	struct cryproc_data *data = kmalloc(sizeof(struct cryproc_data),
			GFP_KERNEL);
	DEBUG("Entering: inode=%p,file=%p",i,f);
	f->private_data = data;
	if(!data)
		return -ENOMEM;
	data->tfm = NULL;
	init_rwsem(&data->sem);
	data->algo[0] = '\0';
	data->algo_in = FALSE;
	data->key[0] = data->key[1] = '\0';
	data->key_in = FALSE;
	data->size[0] = '\0';
	data->size_in = FALSE;	
	data->failed = FALSE;
	data->bytes_done = 0;
	data->output = NULL;
	data->output_size = 0;
	data->total_prev_output = 0;
	data->tail_len = 0;
	memset(data->iv,'\0',MAX_IVLEN);
	return 0;
}

static ssize_t cryproc_read(struct file *file, char *buf,
		size_t size, loff_t *ppos)
{
	struct cryproc_data *data;
	int max;
	data = (struct cryproc_data *)file->private_data;
	down_read(&data->sem);
	DEBUG("Entering: file=%p,buf=%p,size=%i,*ppos=%lli",file,buf,size,*ppos);
	DEBUG_DATA(data);
	if (data->failed)
		return_rup(&data->sem,-EIO);
	if (!data->tfm || !data->algo_in || !data->key_in || !data->size_in)
		return_rup(&data->sem,-EAGAIN);
	if (crypto_tfm_alg_type(data->tfm)==CRYPTO_ALG_TYPE_DIGEST
			&& data->output_size > 0) {
		if (*ppos > data->output_size)
			return_rup(&data->sem,-EINVAL);
		max = size < data->output_size-*ppos ? size 
			: data->output_size-*ppos;
		/*DEBUG("max: %i",max);*/
		if (copy_to_user(buf,data->output+*ppos,max))
			return_rup(&data->sem,-EFAULT);
		*ppos+=max;
		return_rup(&data->sem,max);
	}
	if (crypto_tfm_alg_type(data->tfm)==CRYPTO_ALG_TYPE_CIPHER
			&& data->output && data->output_size > 0) {
		char *out;
		/*DEBUG("total_prev_output=%i,output_size=%i",
			data->total_prev_output,data->output_size);*/
		if (*ppos > data->total_prev_output+data->output_size
				|| *ppos < data->total_prev_output)
			return_rup(&data->sem,-EINVAL);
		max = size < data->total_prev_output+data->output_size-*ppos ?
			size : data->total_prev_output+data->output_size-*ppos;
		DEBUG("max: %i",max);
		if (max==0) {
			return_rup(&data->sem,0);
		}
		out = data->output + *ppos - data->total_prev_output;
		if (copy_to_user(buf,out,max))
			return_rup(&data->sem,-EFAULT);
		*ppos+=max;
		return_rup(&data->sem,max);
	}
	if (crypto_tfm_alg_type(data->tfm)==CRYPTO_ALG_TYPE_COMPRESS
			&& data->output && data->output_size > 0) {
		char *out;
		/*DEBUG("total_prev_output=%i,output_size=%i",
			data->total_prev_output,data->output_size);*/
		if (*ppos > data->total_prev_output+data->output_size
				|| *ppos < data->total_prev_output)
			return_rup(&data->sem,-EINVAL);
		max = size < data->total_prev_output+data->output_size-*ppos ?
			size : data->total_prev_output+data->output_size-*ppos;
		DEBUG("max: %i",max);
		if (max==0) {
			return_rup(&data->sem,0);
		}
		out = data->output + *ppos - data->total_prev_output;
		if (copy_to_user(buf,out,max))
			return_rup(&data->sem,-EFAULT);
		*ppos+=max;
		return_rup(&data->sem,max);
	}

	return_rup(&data->sem,-EINVAL);
}

/* A write to cryproc must follow the following format:
 * algorithm_name\n
 * data_size\n
 * key\n]
 * data
 *
 * algorithm_name and data_size and key must be ASCII-encoded and must not
 * exceed their corresponding maximum lengths. The key should be a string
 * of hexadecimal bytes, without the leading 0x and is ignored if the specified
 * algorithm is unkeyed (e.g. compression). If data is not written
 * according to this format, all subsequent writes will fail until the file
 * is reopened.
 */
static ssize_t cryproc_write(struct file *file, const char *buf, size_t size,
		loff_t *ppos)
{
	char *buffer; /*kernel-space buffer*/
	int result;
	struct cryproc_data *data;

	data = (struct cryproc_data *)file->private_data;
	down_write(&data->sem);
	DEBUG("Entering: buf=%p,size=%i,*ppos=%lli,data=%p",buf,size,*ppos,data);
	DEBUG_DATA(data);
	if (data->failed)
		return_wup(&data->sem,-EIO);
	buffer = kmalloc(size+data->tail_len,GFP_KERNEL);
	if (!buffer)
		return_wup(&data->sem,-ENOMEM);
	if(data->tail_len > 0) {
		memcpy(buffer,data->tail,data->tail_len);
	}
	if (copy_from_user(buffer+data->tail_len,buf,size)) {
		kfree(buffer);
		return_wup(&data->sem,-EFAULT);
	}
	result = handle_write_buffer(buffer,size+data->tail_len,data);
	DEBUG("result=%i",result);
	if (result < 0) {
		kfree(buffer);
		return_wup(&data->sem,result);
	}
	
	kfree(buffer);
	return_wup(&data->sem,size);
}

static int try_reading_algo(const char **ptr,const char *buf,size_t size,
		struct cryproc_data *data)
{
	int str_done;
	if (read_till_newline(data->algo,*ptr,buf+size-*ptr,
			CRYPTO_MAX_ALG_NAME,ptr,&str_done)) {
		if (str_done) {
			data->algo_in = TRUE;
		}
	} else {
		/*if no newline follows, fail due to invalid format*/
		data->failed = TRUE;
		ERROR("Missing newline after algo");
		return -EIO;
	}
	return 0;
}

static int try_reading_size(const char **ptr,const char *buf,size_t size,
		struct cryproc_data *data)
{
	int str_done;
	if (read_till_newline(data->size,*ptr,buf+size-*ptr,SIZE_MAX,
			ptr,&str_done)) {
		if (str_done) {
			/*convert the string to a number*/
			char *np; /*pointer to the part of the string that wasn't parsed*/
			data->size_in = TRUE;
			data->data_size = simple_strtol(data->size,&np,0);
			if (*np) {
				data->failed = TRUE;
				ERROR("Invalid numeric format for size");
				return -EIO;
			}
		}
	} else {
		/*if no newline follows, fail due to invalid format*/
		data->failed = TRUE;
		ERROR("Missing newline after size");
		return -EIO;
	}
	return 0;
}

static int try_reading_key(const char **ptr,const char *buf,size_t size,
		struct cryproc_data *data)
{
	int str_done;
	int flags;
	if (read_till_newline(data->key,*ptr,size+buf-*ptr,KEY_MAX+1,
			ptr,&str_done)) {
		if (str_done) {
			data->key_in = TRUE;
			data->key_length = hex_string_to_bytes(data->key+1,KEY_MAX);
			if (data->key_length==-1) {
				data->failed = TRUE;
				ERROR("Invalid key format");
				return -EIO;
			}
			/* Find out the requested algorithm flags */
			switch(tolower(data->key[0])) {
			case 'c': flags = CRYPTO_TFM_MODE_ECB; break;
			case 'b': flags = CRYPTO_TFM_MODE_CBC; break;
			case 'f': flags = CRYPTO_TFM_MODE_CFB; break;
			case 't': flags = CRYPTO_TFM_MODE_CTR; break;
			default: flags = 0; break;
			}
			/* Create tfm based on algorithm name and flags */
			data->tfm = crypto_alloc_tfm(data->algo,flags);
			if (!data->tfm) {
				data->failed = TRUE;
				ERROR("Failed to allocate tfm for algorithm %s",data->algo);
				return -EIO;
			}
			/* Algorithm initialization */
			switch(crypto_tfm_alg_type(data->tfm)) {
			case CRYPTO_ALG_TYPE_DIGEST:
				/* if key starts with 'H', use HMAC*/
				if(data->key[0]=='H') {
					crypto_hmac_init(data->tfm,data->key+1,
							&data->key_length);
				} else {
					crypto_digest_init(data->tfm);
					if (data->tfm->crt_u.digest.dit_setkey) {
						if (crypto_digest_setkey (data->tfm, data->key+1,
								data->key_length)) {
							ERROR("Setting key for algorithm %s failed",
									data->algo);
						}
					}
				}
				break;
			case CRYPTO_ALG_TYPE_COMPRESS:
				/* No initialization required */
				break;
			case CRYPTO_ALG_TYPE_CIPHER:
				if(crypto_cipher_setkey(data->tfm,data->key+1,
						data->key_length)) {
					ERROR("Setting key for algorithm %s failed",data->algo);
					return -EIO;
				}
				crypto_cipher_set_iv(data->tfm,data->iv,
					crypto_tfm_alg_ivsize(data->tfm));
				break;
			}
		}
	} else {
		/*if no newline follows, fail due to invalid format*/
		data->failed = TRUE;
		ERROR("Missing newline after key");
		return -EIO;
	}
	return 0;
}

static int handle_data_digest(const char **ptr,const char *buf,size_t size,
		struct cryproc_data *data)
{
	struct scatterlist sg;
	int max;
	
	sg.page = virt_to_page(*ptr);
	sg.offset = offset_in_page(*ptr);
	max = buf+size-*ptr < data->data_size-data->bytes_done ?
		buf+size-*ptr : data->data_size-data->bytes_done;
	sg.length = max;
	data->bytes_done+=max;
	/* if key starts with 'H', use HMAC*/
	if(data->key[0]=='H')
		crypto_hmac_update(data->tfm,&sg,1);
	else
		crypto_digest_update(data->tfm,&sg,1);
	if (data->bytes_done>=data->data_size) {
		data->output_size = crypto_tfm_alg_digestsize(data->tfm);
		kfree(data->output);
		data->output = kmalloc(data->output_size,GFP_KERNEL);
		if (!data->output)
			return -ENOMEM;
		if(data->key[0]=='H') {
			crypto_hmac_final(data->tfm,data->key+1,
					&data->key_length,data->output);
		} else {
			crypto_digest_final(data->tfm,data->output);
		}
	}
	return size;
}

static int handle_data_compress(const char **ptr,const char *buf,size_t size,
		struct cryproc_data *data)
{
	int max;
	int old_output_size;
	int result;

	max = buf+size-*ptr < data->data_size-data->bytes_done ?
		buf+size-*ptr : data->data_size-data->bytes_done;
	old_output_size = data->output_size;
	kfree(data->output);
	data->output_size = DEFLATE_BUFSIZE;
	data->output = kmalloc(data->output_size,GFP_KERNEL);
	if(!data->output) {
		data->output_size = 0;
		return -ENOMEM;
	}
	data->bytes_done += max;
	data->total_prev_output+=old_output_size;
	if(data->key[0]=='S') {
		result = crypto_comp_compress(data->tfm,*ptr,max,
				data->output,&data->output_size);
	} else {
		result = crypto_comp_decompress(data->tfm,*ptr,max,
				data->output,&data->output_size);
	}
	if(result) {
		ERROR("Compression operation \"%c\" failed with code %i for "
				"algorithm %s",data->key[0],result,data->algo);
		data->failed = TRUE;
		return -EIO;
	}
	return max;
}

static int handle_data_cipher(const char **ptr,const char *buf,size_t size,
		struct cryproc_data *data)
{
	int max;
	int block_size;
	int result;
	struct scatterlist sg;

	max = buf+size-*ptr < data->data_size-data->bytes_done ?
		buf+size-*ptr : data->data_size-data->bytes_done;
	/* Ciphers require input data to always be a complete
	 * number of blocks, otherwise encryption and decryption
	 * fail*/
	block_size = crypto_tfm_alg_blocksize(data->tfm);
	data->tail_len = max%block_size;
	if (data->tail_len > MAX_IVLEN) {
		return -E2BIG;
	}
	max -= data->tail_len;
	memcpy(data->tail,*ptr+max,data->tail_len);
	data->bytes_done += max;
	if (max == 0) {
		return size;
	}
	sg.page = virt_to_page(*ptr);
	sg.offset = offset_in_page(*ptr);
	sg.length = max;
	if(isupper(data->key[0])) {
		result = crypto_cipher_encrypt(data->tfm,&sg,&sg,max);
	} else {
		result = crypto_cipher_decrypt(data->tfm,&sg,&sg,max);
	}
	if(result) {
		ERROR("Cipher operation \"%c\" failed with code %i for "
			"algorithm %s",data->key[0],result,data->algo);
		data->failed = TRUE;
		return -EIO;
	}
	kfree(data->output);
	data->output = kmalloc(max,GFP_KERNEL);
	if(!data->output)
		return -ENOMEM;
	memcpy(data->output,*ptr,max);
	data->total_prev_output+=data->output_size;
	data->output_size = sg.length;
	return max;
}

static ssize_t handle_write_buffer(const char *buf,size_t size,
		struct cryproc_data *data)
{
	const char *ptr; /* parsing position indicator */
	int result; /* result of helper functions */

	ptr = buf;

	DEBUG("Entering: buf=%p,size=%i",buf,size);
	DEBUG_DATA(data);
	if (data->failed)
		return -EIO;	
	
	/* Read in the header if we haven't done so yet */
	if (!data->algo_in) {
		if ( (result = try_reading_algo(&ptr,buf,size,data))!=0 )
			return result;
	}
	if (!data->size_in) {
		if ( (result = try_reading_size(&ptr,buf,size,data))!=0 )
			return result;
	}
	if (!data->key_in) {
		if ( (result = try_reading_key(&ptr,buf,size,data))!=0 )
			return result;
	}
	/*Perform operations on data*/
	if (data->algo_in && data->size_in && data->key_in) {
		if (data->bytes_done>=data->data_size)
			return size;

		switch (crypto_tfm_alg_type(data->tfm)) {
			case CRYPTO_ALG_TYPE_DIGEST:
				return handle_data_digest(&ptr,buf,size,data);
				break;
			case CRYPTO_ALG_TYPE_COMPRESS:
				return handle_data_compress(&ptr,buf,size,data);
				break;
			case CRYPTO_ALG_TYPE_CIPHER:
				return handle_data_cipher(&ptr,buf,size,data);
				break;
			default:
				return -ENOSYS;
		}
	}

	return size;
}

static int cryproc_release(struct inode *inode, struct file *file)
{
	DEBUG("Entering");
	if (file->private_data) {
		struct cryproc_data *data = ((struct cryproc_data *)file->private_data);
		DEBUG_DATA(data);
		if (!data->failed && data->tfm)
			crypto_free_tfm(data->tfm);
		kfree(data->output);
		kfree(file->private_data);
	}
	DEBUG("Quitting");
	return 0;
}

static struct file_operations cryproc_ops = {
	.open           = cryproc_open,
	.read           = cryproc_read,
	.write          = cryproc_write,
	.release        = cryproc_release
};

static int __init cryproc_init(void)
{
	/*Create file in proc*/
	struct proc_dir_entry *entry;
	DEBUG("Loading module");
	entry = create_proc_entry(proc_file_name, S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, NULL);
	if (entry) {
		entry->proc_fops = &cryproc_ops;
		entry->owner = THIS_MODULE;
		DEBUG("Created proc entry");
	} else {
		ERROR("Couldn't create entry in proc filesystem.");
	}
		
	return 0;
}

static void __exit cryproc_exit(void)
{
	DEBUG("Unloading module");
	remove_proc_entry(proc_file_name, NULL);
}

MODULE_AUTHOR("Michal Kosmulski <mkosmul (at) users (dot) sourceforge (dot) net>");
MODULE_DESCRIPTION("Access to CryptoAPI algorithms through the proc filesystem");
MODULE_LICENSE("GPL");
module_init(cryproc_init)
module_exit(cryproc_exit)

