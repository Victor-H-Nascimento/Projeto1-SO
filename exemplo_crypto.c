#include <crypto/internal/skcipher.h>
#include <linux/module.h>
#include <linux/crypto.h>

#define SYMMETRIC_KEY_LENGTH 32
#define CIPHER_BLOCK_SIZE 16

/* The world's favourite password */
static char *password = "password123";

module_param(password, charp, 0000);
MODULE_PARM_DESC(password, "Chave para cryptografia");

struct tcrypt_result
{
    struct completion completion;
    int err;
};

/*struct scatterlist
{
#ifdef CONFIG_DEBUG_SG
    unsigned long sg_magic;
#endif
    unsigned long page_link;
    unsigned int offset;
    unsigned int length;
    dma_addr_t dma_address;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
    unsigned int dma_length;
#endif
};*/
struct skcipher_def
{
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
    char *scratchpad;
    char *ciphertext;
    char *ivdata;
};

static struct skcipher_def sk;

static void test_skcipher_finish(struct skcipher_def *sk)
{
    if (sk->tfm)
        crypto_free_skcipher(sk->tfm);
    if (sk->req)
        skcipher_request_free(sk->req);
    if (sk->ivdata)
        kfree(sk->ivdata);
    if (sk->scratchpad)
        kfree(sk->scratchpad);
    if (sk->ciphertext)
        kfree(sk->ciphertext);
}

static int test_skcipher_result(struct skcipher_def *sk, int rc)
{
    switch (rc)
    {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err)
        {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
                rc, sk->result.err);
        break;
    }

    init_completion(&sk->result.completion);

    return rc;
}

static void test_skcipher_callback(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;
    /* int ret; */

    if (error == -EINPROGRESS)
        return;

    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");

    /* decrypt data */
    /*
    memset((void*)sk.scratchpad, '-', CIPHER_BLOCK_SIZE);
    ret = crypto_skcipher_decrypt(sk.req);
    ret = test_skcipher_result(&sk, ret);
    if (ret)
        return;

    sg_copy_from_buffer(&sk.sg, 1, sk.scratchpad, CIPHER_BLOCK_SIZE);
    sk.scratchpad[CIPHER_BLOCK_SIZE-1] = 0;

    pr_info("Decryption request successful\n");
    pr_info("Decrypted: %s\n", sk.scratchpad);
    */
}

static int test_skcipher_encrypt(char *plaintext, char *password,
                                 struct skcipher_def *sk)
{
    int ret = -EFAULT;
    unsigned char key[SYMMETRIC_KEY_LENGTH];

    if (!sk->tfm)
    {
        sk->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
        if (IS_ERR(sk->tfm))
        {
            pr_info("could not allocate skcipher handle\n");
            return PTR_ERR(sk->tfm);
        }
    }
    
    pr_info("--Pos crypto_alloc_skcipher--");
    pr_info("sk->tfm: %x", sk->tfm);
    pr_info("&sk->tfm: %x", &sk->tfm);
    pr_info("*sk->tfm: %x", *sk->tfm);
    if (!sk->req)
    {
        sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL);
        if (!sk->req)
        {
            pr_info("could not allocate skcipher request\n");
            ret = -ENOMEM;
            goto out;
        }
    }
    pr_info("--Pos skcipher_request_alloc--");
    pr_info("sk->req: %x", sk->req);
    pr_info("&sk->req: %x", &sk->req);
    pr_info("*sk->req: %x", *sk->req);
    skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  test_skcipher_callback,
                                  &sk->result);

    /* clear the key */
    memset((void *)key, '\0', SYMMETRIC_KEY_LENGTH);

    /* Use the world's favourite password */
    sprintf((char *)key, "%s", password);

    /* AES 256 with given symmetric key */
    if (crypto_skcipher_setkey(sk->tfm, key, SYMMETRIC_KEY_LENGTH))
    {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    pr_info("--Pos crypto_skcipher_setkey--");
    pr_info("sk->tfm: %x", sk->tfm);
    pr_info("&sk->tfm: %x", &sk->tfm);
    pr_info("*sk->tfm: %x", *sk->tfm);

    pr_info("Symmetric key: %s\n", key);
    pr_info("Plaintext: %s\n", plaintext);

    if (!sk->ivdata)
    {
        /* see https://en.wikipedia.org/wiki/Initialization_vector */
        sk->ivdata = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
        if (!sk->ivdata)
        {
            pr_info("could not allocate ivdata\n");
            goto out;
        }
        get_random_bytes(sk->ivdata, CIPHER_BLOCK_SIZE);
    }
    pr_info("--Pos kmalloc de sk->ivdata--");
    pr_info("sk->ivdata: %x", sk->ivdata);
    pr_info("&sk->ivdata: %x", &sk->ivdata);
    pr_info("*sk->ivdata: %x", *sk->ivdata);

    if (!sk->scratchpad)
    {
        /* The text to be encrypted */
        sk->scratchpad = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
        if (!sk->scratchpad)
        {
            pr_info("could not allocate scratchpad\n");
            goto out;
        }
    }
    pr_info("--Pos kmalloc de sk->scratchpad--");
    pr_info("sk->scratchpad: %x", sk->scratchpad);
    pr_info("&sk->scratchpad: %x", &sk->scratchpad);
    pr_info("*sk->scratchpad: %x", *sk->scratchpad);

    sprintf((char *)sk->scratchpad, "%s", plaintext);

    pr_info("--Pos sprintf de sk->scratchpad--");
    pr_info("sk->scratchpad: %s", sk->scratchpad);
    pr_info("&sk->scratchpad: %x", &sk->scratchpad);
    pr_info("*sk->scratchpad: %x", *sk->scratchpad);

    sg_init_one(&sk->sg, sk->scratchpad, CIPHER_BLOCK_SIZE);

    pr_info("----Pos sg_init_one----");
    pr_info("sk->sg: %x", sk->sg);
    pr_info("&sk->sg: %x", &sk->sg);
    //pr_info("*sk->sg: %x", *sk->sg);

    skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg,
                               CIPHER_BLOCK_SIZE, sk->ivdata);
    init_completion(&sk->result.completion);

    /* encrypt data */
    ret = crypto_skcipher_encrypt(sk->req);
    pr_info("--Pos crypto_skcipher_encrypt--");
    pr_info("sk->req: %x\n", sk->req);
    pr_info("&sk->req: %x\n", &sk->req);
    pr_info("*sk->req: %x\n", *sk->req);

    pr_info("--Scatterlist--");
    pr_info("sk->sg.page_link: %x\n", sk->sg.page_link);
    pr_info("&sk->sg.page_link: %x\n", &sk->sg.page_link);
    //pr_info("*sk->sg.page_link: %x\n", *sk->sg.page_link);
    pr_info("sk->sg.offset: %x\n", sk->sg.offset);
    pr_info("&sk->sg.offset: %x\n", &sk->sg.offset);
    //pr_info("*sk->sg.offset: %x\n", *sk->sg.offset);
    pr_info("sk->sg.length: %x\n", sk->sg.length);
    pr_info("&sk->sg.length: %x\n", &sk->sg.length);
    //pr_info("*sk->sg.length: %x\n", *sk->sg.length);

    ret = test_skcipher_result(sk, ret);
    if (ret)
        goto out;

    pr_info("Encryption request successful\n");

out:
    return ret;
}

int cryptoapi_init(void)
{
    pr_info("--------------MODULE ON----------------");

    pr_info("---------------TESTING1----------------");

    sk.tfm = NULL;
    sk.req = NULL;
    sk.scratchpad = NULL;
    sk.ciphertext = NULL;
    sk.ivdata = NULL;

    test_skcipher_encrypt("Paulo", password, &sk);
    /*pr_info("---------------TESTING2----------------");

    sk.tfm = NULL;
    sk.req = NULL;
    sk.scratchpad = NULL;
    sk.ciphertext = NULL;
    sk.ivdata = NULL;

    test_skcipher_encrypt("Malaquias", password, &sk);*/
    return 0;
}

void cryptoapi_exit(void)
{
    test_skcipher_finish(&sk);
}

module_init(cryptoapi_init);
module_exit(cryptoapi_exit);

MODULE_AUTHOR("Meninos");
MODULE_DESCRIPTION("Criptografa as coisas");
MODULE_LICENSE("GPL");
