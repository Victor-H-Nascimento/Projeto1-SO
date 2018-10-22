#include <linux/init.h>    // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>  // Core header for loading LKMs into the kernel
#include <linux/device.h>  // Header to support the kernel Driver Model
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/fs.h>      // Header for the Linux file system support
#include <linux/uaccess.h> // Required for the copy to user function
#include <linux/module.h>
#include <crypto/internal/hash.h>
#include <linux/crypto.h>
#include <crypto/internal/skcipher.h>

#define SYMMETRIC_KEY_LENGTH 32
#define CIPHER_BLOCK_SIZE 16

#define SHA256_LENGTH 32
#define DEVICE_NAME "crypto" ///< The device will appear at /dev/ebbchar using this value
#define CLASS_NAME "cpt"     ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");                                                ///< The license type -- this affects available functionality
MODULE_AUTHOR("Joao & Murilo & Victor");                              ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Modulo de Linux para cryptografar uma mensagem"); ///< The description -- see modinfo
MODULE_VERSION("0.1");                                                ///< A version number to inform users

struct tcrypt_result
{
    struct completion completion;
    int err;
};

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
static char *key = "0123456789ABCDEF";

static int majorNumber;                    ///< Stores the device number -- determined automatically
static char message[256] = {0};            ///< Memory for the string that is passed from userspace
static short size_of_message;              ///< Used to remember the size of the string stored
static int numberOpens = 0;                ///< Counts the number of times the device is opened
static struct class *cryptoClass = NULL;   ///< The device-driver class struct pointer
static struct device *cryptoDevice = NULL; ///< The device-driver device struct pointer

//receber por parametros
module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para cryptografia");

// The prototype functions for the character driver -- must come before the struct definition
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static void test_skcipher_finish(struct skcipher_def *sk);
static void test_skcipher_callback(struct crypto_async_request *req, int error);
static int test_skcipher_result(struct skcipher_def *sk, int rc);
static int test_skcipher_encrypt(char *plaintext, char *password, struct skcipher_def *sk, char opcao);
static char gerarHash(char *hashMessage, int sizeMessage);
static void hexdump(unsigned char *buf, unsigned int len);

static struct file_operations fops =
    {
        .open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .release = dev_release,
};

static int __init crypto_init(void)
{
    printk(KERN_INFO "CryptoModule: modulo crypto inicializado com a chave: %s.\n", key);

    // Try to dynamically allocate a major number for the device -- more difficult but worth it
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0)
    {
        printk(KERN_ALERT "CryptoModule: erro ao registrar o major number.\n");
        return majorNumber;
    }
    printk(KERN_INFO "CryptoModule: registrado corretamente com o major number: %d.\n", majorNumber);
    // Register the device class
    cryptoClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(cryptoClass))
    { // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "CryptoModule: falha ao registrar o device class.\n");
        return PTR_ERR(cryptoClass); // Correct way to return an error on a pointer
    }
    printk(KERN_INFO "CryptoModule: dispositivo registrado corretamente.\n");

    // Register the device driver
    cryptoDevice = device_create(cryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(cryptoDevice))
    {                               // Clean up if there is an error
        class_destroy(cryptoClass); // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "CryptoModule: falha ao criar o dispositivo.\n");
        return PTR_ERR(cryptoDevice);
    }
    printk(KERN_INFO "CryptoModule: device class criado corretamente.\n"); // Made it! device was initialized
    return 0;
}

static void __exit crypto_exit(void)
{
    device_destroy(cryptoClass, MKDEV(majorNumber, 0)); // remove the device
    class_unregister(cryptoClass);                      // unregister the device class
    class_destroy(cryptoClass);                         // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);        // unregister the major number
    printk(KERN_INFO "CryptoModule: modulo finalizado, ate mais!\n");
}

static int dev_open(struct inode *inodep, struct file *filep)
{
    numberOpens++;
    printk(KERN_INFO "CryptoModule: dispositivo aberto %d vez(es).\n", numberOpens);
    return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    int error_count = 0;
    size_of_message = strlen(message);
    // copy_to_user has the format ( * to, *from, size) and returns 0 on success
    error_count = copy_to_user(buffer, message, size_of_message);

    if (error_count == 0)
    { // if true then have success
        printk(KERN_INFO "CryptoModule: enviado %d caracteres para o usuario.\n", size_of_message);
        return (size_of_message = 0); // clear the position to the start and return 0
    }
    else
    {
        printk(KERN_INFO "CryptoModule: falha ao enviar %d caracteres ao usuario.\n", error_count);
        return -EFAULT; // Failed -- return a bad address message (i.e. -14)
    }
    strcpy(message, '\0');
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{                                   // len possui a quantidade de caracteres escritos
    char opcao = buffer[0];         //pegar a opcao do usuario
    sprintf(message, "%s", buffer); // appending received string with its length
    memmove(message, message + 1, strlen(message));
    size_of_message = strlen(message); // store the length of the stored message
    printk(KERN_INFO "Crypto: Message -> %s", message);

    sk.tfm = NULL;
    sk.req = NULL;
    sk.scratchpad = NULL;
    sk.ciphertext = NULL;
    sk.ivdata = NULL;

    switch (opcao)
    {
    case 'c':
        printk("Cryptografar");
        test_skcipher_encrypt(message, key, &sk, opcao);
        test_skcipher_finish(&sk);
        break;

    case 'd':
        printk("Descriptografar");
        test_skcipher_encrypt(message, key, &sk, opcao);
        test_skcipher_finish(&sk);
        break;

    case 'h':
        printk("Cryptografar HASH");
        gerarHash(message, strlen(message));
        break;
    }

    return len;
}
static int dev_release(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "CryptoModule: dispositivo fechado com sucesso.\n");
    return 0;
}

static char gerarHash(char *hashMessage, int sizeMessage)
{

    char *plaintext = hashMessage;
    char hash_sha256[SHA256_LENGTH];
    struct crypto_shash *sha256;
    struct shash_desc *shash;
    int i;
    char str[SHA256_LENGTH * 2 + 1];

    sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256))
        return -1;

    shash =
        kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256),
                GFP_KERNEL);
    if (!shash)
        return -ENOMEM;

    shash->tfm = sha256;
    shash->flags = 0;

    if (crypto_shash_init(shash))
        return -1;

    if (crypto_shash_update(shash, plaintext, strlen(plaintext)))
        return -1;

    if (crypto_shash_final(shash, hash_sha256))
        return -1;

    //show_hash_result(plaintext, hash_sha256);

    pr_info("sha256 test for string: \"%s\"\n", plaintext);
    for (i = 0; i < SHA256_LENGTH; i++)
        sprintf(&str[i * 2], "%02x", (unsigned char)hash_sha256[i]);
    str[i * 2] = 0;
    printk("%s - %i\n ", str, strlen(str));
    strcpy(message, str);

    kfree(shash);
    crypto_free_shash(sha256);

    return 0;
}

static int test_skcipher_encrypt(char *plaintext, char *password, struct skcipher_def *sk, char opcao)
{
    int ret = -EFAULT;
    unsigned char crypto_key[SYMMETRIC_KEY_LENGTH];
    char *aux;
    int i;

    if (!sk->tfm)
    {
        sk->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
        if (IS_ERR(sk->tfm))
        {
            pr_info("could not allocate skcipher handle\n");
            return PTR_ERR(sk->tfm);
        }
    }

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

    skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_callback, &sk->result);

    /* clear the key */
    memset((void *)crypto_key, '\0', SYMMETRIC_KEY_LENGTH);

    /* Use the world's favourite password */
    sprintf((char *)crypto_key, "%s", password);

    /* AES 256 with given symmetric key */
    if (crypto_skcipher_setkey(sk->tfm, crypto_key, SYMMETRIC_KEY_LENGTH))
    {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    //pr_info("Symmetric key: %s\n", key);
    //pr_info("Plaintext: %s\n", plaintext);

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

    sprintf((char *)sk->scratchpad, "%s", plaintext);
    sg_init_one(&sk->sg, sk->scratchpad, CIPHER_BLOCK_SIZE);
    skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg, CIPHER_BLOCK_SIZE, sk->ivdata);
    init_completion(&sk->result.completion);

    switch (opcao)
    {
    case 'c':
        ret = crypto_skcipher_encrypt(sk->req);

        pr_info("Encrypt:\n");
        aux = NULL;
        aux = sg_virt(&sk->sg);
        strcpy(message, aux);
        hexdump(aux, strlen(aux));

        ret = test_skcipher_result(sk, ret);
        if (ret)
            goto out;

        pr_info("Encryption request successful\n");
        break;
    case 'd':
        ret = crypto_skcipher_decrypt(sk->req);
        aux = NULL;
        aux = sg_virt(&sk->sg);
        strcpy(message, aux);
        pr_info("Decrypt: %s", aux);

        ret = test_skcipher_result(sk, ret);
        if (ret)
            goto out;

        pr_info("Decryption request successful\n");
        break;
    }

out:
    return ret;
}

static int test_skcipher_result(struct skcipher_def *sk, int rc)
{
    switch (rc)
    {
    case 0:
        break;
    case -EINPROGRESS:
        pr_info("Pudim!\n");
        break;
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

    if (error == -EINPROGRESS)
        return;

    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}
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
static void hexdump(unsigned char *buf, unsigned int len)
{
    printk("len = %u\n", len);
    while (len--)
    {

        pr_info("%02x", *buf++);
    }

    printk("\n");
}
module_init(crypto_init);
module_exit(crypto_exit);