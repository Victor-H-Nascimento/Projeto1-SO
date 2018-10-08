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

#include <linux/init.h>   // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h> // Core header for loading LKMs into the kernel
#include <linux/device.h> // Header to support the kernel Driver Model
#include <linux/crypto.h>
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/fs.h>      // Header for the Linux file system support
#include <linux/uaccess.h> // Required for the copy to user function
#include <linux/scatterlist.h>

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
static struct class *ebbcharClass = NULL;   ///< The device-driver class struct pointer
static struct device *ebbcharDevice = NULL; ///< The device-driver device struct pointer

//receber por parametros

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para cryptografia");

// The prototype functions for the character driver -- must come before the struct definition
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static void my_test(void);

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
static int __init ebbchar_init(void)
{
    pr_info(KERN_INFO "CryptoModule: modulo crypto inicializado com a chave: %s.\n", key);
    my_test();
    // Try to dynamically allocate a major number for the device -- more difficult but worth it
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0)
    {
        pr_info(KERN_ALERT "CryptoModule: erro ao registrar o major number.\n");
        return majorNumber;
    }
    pr_info(KERN_INFO "CryptoModule: registrado corretamente com o major number: %d.\n", majorNumber);
    // Register the device class
    ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(ebbcharClass))
    { // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        pr_info(KERN_ALERT "CryptoModule: falha ao registrar o device class.\n");
        return PTR_ERR(ebbcharClass); // Correct way to return an error on a pointer
    }
    pr_info(KERN_INFO "CryptoModule: dispositivo registrado corretamente.\n");

    // Register the device driver
    ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(ebbcharDevice))
    {                                // Clean up if there is an error
        class_destroy(ebbcharClass); // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        pr_info(KERN_ALERT "CryptoModule: falha ao criar o dispositivo.\n");
        return PTR_ERR(ebbcharDevice);
    }
    pr_info(KERN_INFO "CryptoModule: device class criado corretamente.\n"); // Made it! device was initialized
    return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit ebbchar_exit(void)
{
    device_destroy(ebbcharClass, MKDEV(majorNumber, 0)); // remove the device
    class_unregister(ebbcharClass);                      // unregister the device class
    class_destroy(ebbcharClass);                         // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);         // unregister the major number
    pr_info(KERN_INFO "CryptoModule: bjunda, ate mais!\n");
}

/** @brief The device open function that is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep)
{
    numberOpens++;
    pr_info(KERN_INFO "CryptoModule: dispositivo aberto %d vez(es).\n", numberOpens);
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
    // copy_to_user has the format ( * to, *from, size) and returns 0 on success
    error_count = copy_to_user(buffer, message, size_of_message);

    if (error_count == 0)
    { // if true then have success
        pr_info(KERN_INFO "CryptoModule: enviado %d caracteres para o usuario.\n", size_of_message);
        return (size_of_message = 0); // clear the position to the start and return 0
    }
    else
    {
        pr_info(KERN_INFO "CryptoModule: falha ao enviar %d caracteres ao usuario.\n", error_count);
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
{                                      // len possui a quantidade de caracteres escritos
    sprintf(message, "%s", buffer);    // appending received string with its length
    size_of_message = strlen(message); // store the length of the stored message
    pr_info(KERN_INFO "CryptoModule: recebido %zu caracteres do usuario.\n", len);
    return len;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep)
{
    pr_info(KERN_INFO "CryptoModule: dispositivo fechado com sucesso.\n");
    return 0;
}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */

static void crypto_fuction()
{
}
static void decrypto_fuction()
{
}
static void init_crypto()
{
}
static void my_test(void)
{
    uint32_t *input;
    uint32_t *output;
    uint32_t *temp;
    uint32_t texto_criptografado[256];
    unsigned char *src;
    unsigned char *dst;
    size_t blk_len = 16;
    size_t key_len = 16;
    int ret, i, j, num_loops;

    struct crypto_blkcipher *my_tfm;
    struct blkcipher_desc desc;
    struct scatterlist *src_sg;
    struct scatterlist *dst_sg;

    unsigned char my_key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    unsigned char *my_iv;
    void *iv;
    size_t ivsize;
    my_iv = vmalloc(blk_len);
    memset(my_iv, 0, blk_len);

    temp = vmalloc(blk_len);

    src_sg = vmalloc(sizeof(struct scatterlist));
    if (!src_sg)
    {
        pr_info("CryptoModule: failed to alloc src_sg!!!\n");
        goto src_sg_free;
    }
    dst_sg = vmalloc(sizeof(struct scatterlist));
    if (!dst_sg)
    {
        pr_info("CryptoModule: failed to alloc dst_sg!!!\n");
        goto dst_sg_free;
    }
    input = vmalloc(blk_len);
    if (!input)
    {
        pr_info("CryptoModule: failed to alloc input!!!\n");
        goto input_free;
    }
    output = vmalloc(blk_len);
    if (!output)
    {
        pr_info("CryptoModule: failed to alloc output!!!\n");
        goto output_free;
    }
    src = vmalloc(blk_len);
    if (!src)
    {
        pr_info("CryptoModule: failed to alloc src!!!\n");
        goto src_free;
    }
    dst = vmalloc(blk_len);
    if (!dst)
    {
        pr_info("CryptoModule: failed to alloc dst!!!\n");
        goto dst_free;
    }

    my_tfm = crypto_alloc_blkcipher("ecb(aes)", 0, 0);
    if (!my_tfm)
    {
        pr_info("CryptoModule: failed to alloc tfm!!!\n");
        goto crypto_free;
    }

    desc.tfm = my_tfm;
    desc.flags = 0;
    crypto_blkcipher_setkey(my_tfm, my_key, key_len);

    iv = crypto_blkcipher_crt(my_tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(my_tfm);

    memcpy(iv, my_iv, ivsize);

    char texto[256] = {"Mensagem de teste"};

    num_loops = strlen(texto) / 4;
    if ((strlen(texto) % 4) != 0)
    {
        num_loops++;
    }
    pr_info("CryptoModule: Numero de blocos %d", num_loops);
    for (j = 0; j < num_loops; j++)
    {
        for (i = 0; i < 4; i++)
        {
            input[i] = texto[i + (j * 4)];
            *((uint32_t *)(&src[i * 4])) = input[i];
            temp[i] = 0xFFFFFFFF;
            *((uint32_t *)(&dst[i * 4])) = temp[i];
        }

        pr_info("CryptoModule: input: %c,%c,%c,%c\n", input[0], input[1], input[2], input[3]);

        sg_init_one(src_sg, src, blk_len);
        sg_init_one(dst_sg, dst, blk_len);

        ret = crypto_blkcipher_encrypt(&desc, dst_sg, src_sg, src_sg->length);
        if (ret < 0)
            pr_err("CryptoModule: phase one failed %d\n", ret);

        for (i = 0; i < 4; i++)
        {
            output[i] = *((uint32_t *)(&dst[i * 4]));
            texto_criptografado[i + (j * 4)] = output[i];
        }

        pr_info("CryptoModule: output: %x,%x,%x,%x\n", output[0], output[1], output[2], output[3]);
    }
    for (j = 0; j < num_loops; j++)
    {

        for (i = 0; i < 4; i++)
        {
            *((uint32_t *)(&src[i * 4])) = texto_criptografado[i + (j * 4)];
            temp[i] = 0xFFFFFFFF;
            *((uint32_t *)(&dst[i * 4])) = temp[i];
        }

        sg_init_one(src_sg, src, blk_len);
        sg_init_one(dst_sg, dst, blk_len);

        ret = crypto_blkcipher_decrypt(&desc, dst_sg, src_sg, src_sg->length);
        if (ret < 0)
            pr_err("CryptoModule: phase one failed %d\n", ret);

        for (i = 0; i < 4; i++)
        {
            output[i] = *((uint32_t *)(&dst[i * 4]));
        }

        pr_info("CryptoModule: output: %c,%c,%c,%c\n", output[0], output[1], output[2], output[3]);
    }
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
    pr_info("CryptoModule: END!!!\n");
}
module_init(ebbchar_init);
module_exit(ebbchar_exit);