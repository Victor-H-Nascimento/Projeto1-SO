#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>

void my_test(void)
{
    uint32_t *input;
    uint32_t *output;
    uint32_t *temp;
    unsigned char *src;
    unsigned char *dst;
    size_t blk_len = 16;
    size_t key_len = 16;
    int ret;

    struct crypto_blkcipher *my_tfm;
    struct blkcipher_desc desc;
    struct scatterlist *src_sg;
    struct scatterlist *dst_sg;

    unsigned char my_key[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    unsigned char *my_iv;
    void *iv;
    size_t ivsize = 16;
    my_iv = vmalloc(blk_len);
    memset(my_iv, 0, blk_len);

    temp = vmalloc(blk_len);

    src_sg = vmalloc(sizeof(struct scatterlist));
    if (!src_sg)
    {
        printk("MY_TEST: failed to alloc src_sg!!!\n");
        goto src_sg_free;
    }
    dst_sg = vmalloc(sizeof(struct scatterlist));
    if (!dst_sg)
    {
        printk("MY_TEST: failed to alloc dst_sg!!!\n");
        goto dst_sg_free;
    }
    input = vmalloc(blk_len);
    if (!input)
    {
        printk("MY_TEST: failed to alloc input!!!\n");
        goto input_free;
    }
    output = vmalloc(blk_len);
    if (!output)
    {
        printk("MY_TEST: failed to alloc output!!!\n");
        goto output_free;
    }
    src = vmalloc(blk_len);
    if (!src)
    {
        printk("MY_TEST: failed to alloc src!!!\n");
        goto src_free;
    }
    dst = vmalloc(blk_len);
    if (!dst)
    {
        printk("MY_TEST: failed to alloc dst!!!\n");
        goto dst_free;
    }

    my_tfm = crypto_alloc_blkcipher("ecb(aes)", 0, 0);
    if (!my_tfm)
    {
        printk("MY_TEST: failed to alloc tfm!!!\n");
        goto crypto_free;
    }

    desc.tfm = my_tfm;
    desc.flags = 0;
    crypto_blkcipher_setkey(my_tfm, my_key, key_len);

    iv = crypto_blkcipher_crt(my_tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(my_tfm);

    memcpy(iv, my_iv, ivsize);

    input[0] = 0x80000000;
    input[1] = 0x00000000;
    input[2] = 0x00000000;
    input[3] = 0x00000000;
    printk("MY_TEST: input: %x,%x,%x,%x\n", input[0], input[1], input[2], input[3]);

    *((uint32_t *)(&src[0])) = input[0];
    *((uint32_t *)(&src[4])) = input[1];
    *((uint32_t *)(&src[8])) = input[2];
    *((uint32_t *)(&src[12])) = input[3];

    temp[0] = 0xFFFFFFFF;
    temp[1] = 0xFFFFFFFF;
    temp[2] = 0xFFFFFFFF;
    temp[3] = 0xFFFFFFFF;
    *((uint32_t *)(&dst[0])) = temp[0];
    *((uint32_t *)(&dst[4])) = temp[1];
    *((uint32_t *)(&dst[8])) = temp[2];
    *((uint32_t *)(&dst[12])) = temp[3];

    sg_init_one(src_sg, src, blk_len);
    sg_init_one(dst_sg, dst, blk_len);

    ret = crypto_blkcipher_encrypt(&desc, dst_sg, src_sg, src_sg->length);
    if (ret < 0)
        pr_err("MY_TEST: phase one failed %d\n", ret);
    output[0] = *((uint32_t *)(&dst[0]));
    output[1] = *((uint32_t *)(&dst[4]));
    output[2] = *((uint32_t *)(&dst[8]));
    output[3] = *((uint32_t *)(&dst[12]));

    printk("MY_TEST: output: %x,%x,%x,%x\n", output[0], output[1], output[2], output[3]);

    crypto_free_blkcipher(my_tfm);

    vfree(temp);

crypto_free:
    vfree(dst);
dst_free:
    vfree(src);
src_free:
    vfree(output);
output_free:
    vfree(input);
input_free:
    vfree(dst_sg);
dst_sg_free:
    vfree(src_sg);
src_sg_free:
    printk("MY_TEST: END!!!\n");
}

static int test_mod_init(void)
{
    printk("MY_TEST: init.\n");
    my_test();
    return 0;
}

static void test_mod_exit(void)
{
    printk("MY_TEST: exit.\n");
}
module_init(test_mod_init);
module_exit(test_mod_exit);

MODULE_AUTHOR("xana");
MODULE_DESCRIPTION("my test module");
MODULE_LICENSE("GPL");