/**
 * @file   ebbchar.c
 * @author Derek Molloy
 * @date   7 April 2015
 * @version 0.1
 * @brief   An introductory character driver to support the second article of my series on
 * Linux loadable kernel module (LKM) development. This module maps to /dev/ebbchar and
 * comes with a helper C program that can be run in Linux user space to communicate with
 * this the LKM.
 * @see http://www.derekmolloy.ie/ for a full description and follow-up descriptions.
 */

#include <linux/init.h>      // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>    // Core header for loading LKMs into the kernel
#include <linux/device.h>    // Header to support the kernel Driver Model
#include <linux/kernel.h>    // Contains types, macros, functions for the kernel
#include <linux/fs.h>        // Header for the Linux file system support
#include <linux/uaccess.h>   // Required for the copy to user function
#include <linux/module.h>
#include <crypto/internal/hash.h>

#define SHA256_LENGTH 32
#define DEVICE_NAME "crypto" ///< The device will appear at /dev/ebbchar using this value
#define CLASS_NAME "cpt"     ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");                                                ///< The license type -- this affects available functionality
MODULE_AUTHOR("Joao Murilo Victor");                                  ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Modulo de Linux para cryptografar uma mensagem"); ///< The description -- see modinfo
MODULE_VERSION("0.1");                                                ///< A version number to inform users

static char *key = "0123456789ABCDEF";

static int majorNumber;                     ///< Stores the device number -- determined automatically
static char message[256] = {0};             ///< Memory for the string that is passed from userspace
static short size_of_message;               ///< Used to remember the size of the string stored
static int numberOpens = 0;                 ///< Counts the number of times the device is opened
static struct class *cryptoClass = NULL;   ///< The device-driver class struct pointer
static struct device *cryptoDevice = NULL; ///< The device-driver device struct pointer

//receber por parametros
module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para cryptografia");

//prototype
static char gerarHash(char *hashMessage, int sizeMessage);

// The prototype functions for the character driver -- must come before the struct definition
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations fops =
    {
        .open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .release = dev_release,
};

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
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
    {                                // Clean up if there is an error
        class_destroy(cryptoClass); // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "CryptoModule: falha ao criar o dispositivo.\n");
        return PTR_ERR(cryptoDevice);
    }
    printk(KERN_INFO "CryptoModule: device class criado corretamente.\n"); // Made it! device was initialized
    return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit crypto_exit(void)
{
    device_destroy(cryptoClass, MKDEV(majorNumber, 0)); // remove the device
    class_unregister(cryptoClass);                      // unregister the device class
    class_destroy(cryptoClass);                         // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);         // unregister the major number
    printk(KERN_INFO "CryptoModule: bjunda, ate mais!\n");
}

/** @brief The device open function that is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep)
{
    numberOpens++;
    printk(KERN_INFO "CryptoModule: dispositivo aberto %d vez(es).\n", numberOpens);
    return 0;
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case is uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
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
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{   // len possui a quantidade de caracteres escritos
    char opcao = buffer[0];//pegar a opcao do usuario
    sprintf(message, "%s", buffer); // appending received string with its length
    memmove(message, message+1, strlen(message));
    size_of_message = strlen(message);// store the length of the stored message
    printk(KERN_INFO "Crypto: Message -> %s", message);

	switch(opcao)
	{
		case'c':
		printk("Cryptografar");
		break;
	
		case'd':
		printk("Desptografar");
		break;

		case'h':
		printk("Cryptografar HASH");
		gerarHash(message, strlen(message));
		break;

	}

    printk(KERN_INFO "CryptoModule: recebido %zu caracteres do usuario.\n", len);
    return len;
}

static char gerarHash(char *hashMessage, int sizeMessage){

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


/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "CryptoModule: dispositivo fechado com sucesso.\n");
    return 0;
}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(crypto_init);
module_exit(crypto_exit);