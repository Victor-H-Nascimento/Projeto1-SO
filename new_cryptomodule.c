#include <linux/init.h>   // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h> // Core header for loading LKMs into the kernel
#include <linux/device.h> // Header to support the kernel Driver Model
#include <linux/kernel.h> // Contains types, macros, functions for the kernel
#include <linux/fs.h>     // Header for the Linux file system support
#include <linux/slab.h>   //kmalloc
#include <linux/crypto.h>
#include <crypto/sha.h>
#include <crypto/internal/hash.h>
#include <linux/scatterlist.h>
#include <asm/uaccess.h>     // Required for the copy to user function
#define DEVICE_NAME "crypto" ///< The device will appear at /dev/crypto using this value
#define CLASS_NAME "cryp"    ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");                                                               ///< The license type -- this affects available functionality
MODULE_AUTHOR("Murilo & Joao & Victor");                                             ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Dispositivo para criptografia, descriptografia e calculo hash"); ///< The description -- see modinfo
MODULE_VERSION("0.1");                                                               ///< A version number to inform users

static int majorNumber;                        ///< Stores the device number -- determined automatically
static short size_of_message;                  ///< Used to remember the size of the string stored
static int numberOpens = 0;                    ///< Counts the number of times the device is opened
static struct class *cryptocharClass = NULL;   ///< The device-driver class struct pointer
static struct device *cryptocharDevice = NULL; ///< The device-driver device struct pointer

int size = 0;
char *key;
char *encrypted;
char *decrypted;
unsigned char *sha1res;
char *message;

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "key");

static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
void hash(char *in);
void encrypt(char *in);
void decrypt(void);


static struct file_operations fops = {
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
};

static int __init crypto_init(void)
{
    printk(KERN_INFO "Initializing Crypto with key: %s\n", key);
    // Try to dynamically allocate a major number for the device -- more difficult but worth it
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0)
    {
        printk(KERN_ALERT "Crypto failed to register a major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "Crypto: registered correctly with major number %d\n", majorNumber);

    // Register the device class
    cryptocharClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(cryptocharClass))
    { // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(cryptocharClass); // Correct way to return an error on a pointer
    }
    printk(KERN_INFO "Crypto: device class registered correctly\n");

    // Register the device driver
    cryptocharDevice = device_create(cryptocharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(cryptocharDevice))
    {                                   // Clean up if there is an error
        class_destroy(cryptocharClass); // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(cryptocharDevice);
    }
    printk(KERN_INFO "Crypto: device class created correctly\n"); // Made it! device was initialized
    return 0;
}

static void __exit crypto_exit(void)
{
    device_destroy(cryptocharClass, MKDEV(majorNumber, 0)); // remove the device
    class_unregister(cryptocharClass);                      // unregister the device class
    class_destroy(cryptocharClass);                         // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);            // unregister the major number
    printk(KERN_INFO "Crypto: Goodbye from the LKM!\n");
}

static int dev_open(struct inode *inodep, struct file *filep)
{
    numberOpens++;
    printk(KERN_INFO "Crypto: Device has been opened %d time(s)\n", numberOpens);
    return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    int error_count = 0;
    // copy_to_user has the format ( * to, *from, size) and returns 0 on success
    error_count = copy_to_user(buffer, message, size_of_message);

    if (error_count == 0)
    { // if true then have success
        printk(KERN_INFO "Crypto: Sent %d characters to the user\n", size_of_message);
        return (size_of_message = 0); // clear the position to the start and return 0
    }
    else
    {
        printk(KERN_INFO "Crypto: Failed to send %d characters to the user\n", error_count);
        return -EFAULT; // Failed -- return a bad address message (i.e. -14)
    }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
    char opcao = *buffer;
    char *src = kmalloc(strlen(buffer), GFP_ATOMIC);

    switch (opcao)
    {
    case 'c':
        strcpy(src, buffer);
        strsep(&src, " ");
        printk(KERN_INFO "Dado para encriptar: %s", src);
        encrypt(src);
        printk(KERN_INFO "Dado encriptado: %*ph", 16, encrypted);
        message = kmalloc(strlen(encrypted), GFP_ATOMIC);
        strcpy(message, encrypted);
        break;
    case 'd':
        decrypt();
        printk(KERN_INFO "Dado decriptado: %s", decrypted);
        message = kmalloc(strlen(decrypted), GFP_ATOMIC);
        strcpy(message, decrypted);
        break;
    case 'h':
        strcpy(src, buffer);
        strsep(&src, " ");

        hash(src);
        message = kmalloc(SHA1_DIGEST_SIZE, GFP_ATOMIC);
        strcpy(message, sha1res);
        break;
    default:
        printk("Opção inválida");
        break;
    }

    size_of_message = strlen(message); // store the length of the stored message
    return len;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "Crypto: Device successfully closed\n");
    return 0;
}


void hash(char *in)
{
    printk("Mensagem antes do SHA1: %s", in);
    struct shash_desc *desc;
    struct crypto_shash *tfm = crypto_alloc_shash("sha1", 0, 0);
    in = strim(in);
    size_t len = strlen(in);
    size_t desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
    desc = kzalloc(desc_size, GFP_KERNEL);
    sha1res = kmalloc(SHA1_DIGEST_SIZE, GFP_KERNEL);
    memset(sha1res, 0x00, SHA1_DIGEST_SIZE);

    desc->tfm = tfm;
    desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
    crypto_shash_digest(desc, in, len, sha1res);
    kfree(desc);

    printk("SHA1: %*phN\n", SHA1_DIGEST_SIZE, sha1res);
}

void encrypt(char *in)
{
    int i, count, div, modd;
    struct crypto_cipher *tfm;
    in = strim(in);
    div = strlen(in) / 16;
    modd = strlen(in) % 16;
    if (modd > 0)
    {
        div++;
    }
    count = div;
    size = strlen(in);
    encrypted = kmalloc(size * count, GFP_ATOMIC);

    tfm = crypto_alloc_cipher("aes", 0, 16);
    crypto_cipher_setkey(tfm, key, 16);
    for (i = 0; i < count; i++)
    {
        char *c = kmalloc(size, GFP_ATOMIC);
        crypto_cipher_encrypt_one(tfm, c, in);
        if (i == 0)
        {
            strcpy(encrypted, c);
        }
        else
        {
            strcat(encrypted, c);
        }
        in += 16;
    }

    crypto_free_cipher(tfm);
}

void decrypt(void)
{
    int i, count, div, modd;
    struct crypto_cipher *tfm;

    div = size / 16;
    modd = size % 16;
    if (modd > 0)
    {
        div++;
    }
    count = div;

    decrypted = kmalloc(size * count, GFP_ATOMIC);
    tfm = crypto_alloc_cipher("aes", 0, 16);
    crypto_cipher_setkey(tfm, key, 16);

    for (i = 0; i < count; i++)
    {
        char *c = kmalloc(size, GFP_ATOMIC);
        crypto_cipher_decrypt_one(tfm, c, encrypted);
        if (i == 0)
        {
            strcpy(decrypted, c);
        }
        else
        {
            strcat(decrypted, c);
        }
        encrypted += 16;
    }
}

module_init(crypto_init);
module_exit(crypto_exit);
