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
static int majorNumber; ///< Stores the device number -- determined automatically
static uint32_t msg_cryptografada[256];
static char msg_descryptografada[256];
static int num_blocos = 0;
static short size_of_message;               ///< Used to remember the size of the string stored
static int numberOpens = 0;                 ///< Counts the number of times the device is opened
static struct class *ebbcharClass = NULL;   ///< The device-driver class struct pointer
static struct device *ebbcharDevice = NULL; ///< The device-driver device struct pointer
static int tamanho_texto = 0;
static char msg_to_send[256];
//receber por parametros

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para cryptografia");

// The prototype functions for the character driver -- must come before the struct definition
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static void crypto_fuction(char crypto_input[]);
static void decrypto_fuction(void);

static struct file_operations fops =
    {
        .open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .release = dev_release,
};

static int __init ebbchar_init(void)
{
    pr_info("---------------------------------------------------------------");
    pr_info("CryptoModule: Modulo inicializado com a chave: %s.\n", key);
    // Try to dynamically allocate a major number for the device -- more difficult but worth it
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0)
    {
        pr_info("CryptoModule: Erro ao registrar o major number.\n");
        return majorNumber;
    }
    //pr_info(KERN_INFO "CryptoModule: registrado corretamente com o major number: %d.\n", majorNumber);
    // Register the device class
    ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(ebbcharClass))
    { // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        pr_info("CryptoModule: Falha ao registrar o device class.\n");
        return PTR_ERR(ebbcharClass); // Correct way to return an error on a pointer
    }
    //pr_info(KERN_INFO "CryptoModule: dispositivo registrado corretamente.\n");

    // Register the device driver
    ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(ebbcharDevice))
    {                                // Clean up if there is an error
        class_destroy(ebbcharClass); // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        pr_info("CryptoModule: Falha ao criar o dispositivo.\n");
        return PTR_ERR(ebbcharDevice);
    }
    //pr_info(KERN_INFO "CryptoModule: device class criado corretamente.\n"); // Made it! device was initialized
    return 0;
}

static void __exit ebbchar_exit(void)
{
    device_destroy(ebbcharClass, MKDEV(majorNumber, 0)); // remove the device
    class_unregister(ebbcharClass);                      // unregister the device class
    class_destroy(ebbcharClass);                         // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);         // unregister the major number
    pr_info("CryptoModule: Dispositivo encerrado, ate mais!\n");
}

static int dev_open(struct inode *inodep, struct file *filep)
{
    numberOpens++;
    pr_info("CryptoModule: Dispositivo aberto %d vez(es).\n", numberOpens);
    return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    int error_count = 0;
    //decrypto_fuction();
    // copy_to_user has the format ( * to, *from, size) and returns 0 on success
    error_count = copy_to_user(buffer, msg_to_send, tamanho_texto);

    if (error_count == 0)
    { // if true then have success
        pr_info("CryptoModule: Enviado %d caracteres para o usuario.\n", strlen(msg_descryptografada));
        pr_info("CryptoModule: Enviado [%s]", msg_descryptografada);
        return (size_of_message = 0); // clear the position to the start and return 0
    }
    else
    {
        pr_info("CryptoModule: Falha ao enviar %d caracteres ao usuario.\n", error_count);
        return -EFAULT; // Failed -- return a bad address message (i.e. -14)
    }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{ // len possui a quantidade de caracteres escritos
    if ((strcmp((buffer[(strlen(buffer) - 1)]), "c")) == 0)
    {
        static int i;
        crypto_fuction(buffer);
        for (i = 0; i < tamanho_texto; i++)
        {
            msg_to_send[i] = msg_cryptografada[i]; 
        }
    }

    //pr_info("CryptoModule: Escrito %d caracteres no dispositivo", len);
    return len;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
    pr_info("CryptoModule: Dispositivo fechado com sucesso.\n");
    return 0;
}

static void crypto_fuction(char crypto_input[])
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

    unsigned char my_key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    unsigned char *my_iv;
    void *iv;
    size_t ivsize;
    my_iv = vmalloc(blk_len);
    memset(my_iv, 0, blk_len);

    temp = vmalloc(blk_len);

    src_sg = vmalloc(sizeof(struct scatterlist));
    if (!src_sg)
    {
        pr_info("CryptoModule: Failed to alloc src_sg!!!\n");
        goto src_sg_free;
    }
    dst_sg = vmalloc(sizeof(struct scatterlist));
    if (!dst_sg)
    {
        pr_info("CryptoModule: Failed to alloc dst_sg!!!\n");
        goto dst_sg_free;
    }
    input = vmalloc(blk_len);
    if (!input)
    {
        pr_info("CryptoModule: Failed to alloc input!!!\n");
        goto input_free;
    }
    output = vmalloc(blk_len);
    if (!output)
    {
        pr_info("CryptoModule: Failed to alloc output!!!\n");
        goto output_free;
    }
    src = vmalloc(blk_len);
    if (!src)
    {
        pr_info("CryptoModule: Failed to alloc src!!!\n");
        goto src_free;
    }
    dst = vmalloc(blk_len);
    if (!dst)
    {
        pr_info("CryptoModule: Failed to alloc dst!!!\n");
        goto dst_free;
    }

    my_tfm = crypto_alloc_blkcipher("ecb(aes)", 0, 0);
    if (!my_tfm)
    {
        pr_info("CryptoModule: Failed to alloc tfm!!!\n");
        goto crypto_free;
    }

    desc.tfm = my_tfm;
    desc.flags = 0;
    crypto_blkcipher_setkey(my_tfm, my_key, key_len);

    iv = crypto_blkcipher_crt(my_tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(my_tfm);

    memcpy(iv, my_iv, ivsize);

    char texto[256];
    tamanho_texto = strlen(crypto_input);
    num_loops = strlen(crypto_input) / 4;

    if ((strlen(crypto_input) % 4) != 0)
    {
        num_loops++;
    }
    num_blocos = num_loops;

    for (i = 0; i < num_loops * 4; i++)
    {
        texto[i] = " ";
    }

    for (i = 0; i < strlen(crypto_input); i++)
    {
        texto[i] = crypto_input[i];
    }

    pr_info("CryptoModule: Numero de blocos %d", num_loops);
    for (j = 0; j < num_loops; j++)
    {
        for (i = 0; i < 4; i++)
        {
            input[i] = texto[i + (j * 4)];
            *((uint32_t *)(&src[i * 4])) = input[i];
            *((uint32_t *)(&dst[i * 4])) = temp[i];
        }

        //pr_info("CryptoModule: input: %c,%c,%c,%c\n", input[0], input[1], input[2], input[3]);

        sg_init_one(src_sg, src, blk_len);
        sg_init_one(dst_sg, dst, blk_len);

        ret = crypto_blkcipher_encrypt(&desc, dst_sg, src_sg, src_sg->length);
        if (ret < 0)
            pr_err("CryptoModule: Phase one failed %d\n", ret);

        for (i = 0; i < 4; i++)
        {
            output[i] = *((uint32_t *)(&dst[i * 4]));
            texto_criptografado[i + (j * 4)] = output[i];
        }

        //pr_info("CryptoModule: output: %x,%x,%x,%x\n", output[0], output[1], output[2], output[3]);
    }
    for (i = 0; i < strlen(texto); i++)
    {
        msg_cryptografada[i] = texto_criptografado[i];
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
    pr_info("CryptoModule: Mensagem criptografada!\n");
}
static void decrypto_fuction(void)
{
    uint32_t *input;
    uint32_t *output;
    uint32_t *temp;
    uint32_t texto_descriptografado[256];
    unsigned char *src;
    unsigned char *dst;
    size_t blk_len = 16;
    size_t key_len = 16;
    int ret, i, j;

    struct crypto_blkcipher *my_tfm;
    struct blkcipher_desc desc;
    struct scatterlist *src_sg;
    struct scatterlist *dst_sg;

    unsigned char my_key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    unsigned char *my_iv;
    void *iv;
    size_t ivsize;
    my_iv = vmalloc(blk_len);
    memset(my_iv, 0, blk_len);

    temp = vmalloc(blk_len);

    src_sg = vmalloc(sizeof(struct scatterlist));
    if (!src_sg)
    {
        pr_info("CryptoModule: Failed to alloc src_sg!!!\n");
        goto src_sg_free;
    }
    dst_sg = vmalloc(sizeof(struct scatterlist));
    if (!dst_sg)
    {
        pr_info("CryptoModule: Failed to alloc dst_sg!!!\n");
        goto dst_sg_free;
    }
    input = vmalloc(blk_len);
    if (!input)
    {
        pr_info("CryptoModule: Failed to alloc input!!!\n");
        goto input_free;
    }
    output = vmalloc(blk_len);
    if (!output)
    {
        pr_info("CryptoModule: Failed to alloc output!!!\n");
        goto output_free;
    }
    src = vmalloc(blk_len);
    if (!src)
    {
        pr_info("CryptoModule: Failed to alloc src!!!\n");
        goto src_free;
    }
    dst = vmalloc(blk_len);
    if (!dst)
    {
        pr_info("CryptoModule: Failed to alloc dst!!!\n");
        goto dst_free;
    }

    my_tfm = crypto_alloc_blkcipher("ecb(aes)", 0, 0);
    if (!my_tfm)
    {
        pr_info("CryptoModule: Failed to alloc tfm!!!\n");
        goto crypto_free;
    }

    desc.tfm = my_tfm;
    desc.flags = 0;
    crypto_blkcipher_setkey(my_tfm, my_key, key_len);

    iv = crypto_blkcipher_crt(my_tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(my_tfm);

    memcpy(iv, my_iv, ivsize);

    pr_info("CryptoModule: Numero de blocos %d", num_blocos);

    for (j = 0; j < num_blocos; j++)
    {

        for (i = 0; i < 4; i++)
        {
            *((uint32_t *)(&src[i * 4])) = msg_cryptografada[i + (j * 4)];
            *((uint32_t *)(&dst[i * 4])) = temp[i];
        }

        sg_init_one(src_sg, src, blk_len);
        sg_init_one(dst_sg, dst, blk_len);

        ret = crypto_blkcipher_decrypt(&desc, dst_sg, src_sg, src_sg->length);
        if (ret < 0)
            pr_err("CryptoModule: Phase one failed %d\n", ret);

        for (i = 0; i < 4; i++)
        {
            output[i] = *((uint32_t *)(&dst[i * 4]));
            texto_descriptografado[i + (j * 4)] = output[i];
        }
        //pr_info("CryptoModule: output: %c,%c,%c,%c\n", output[0], output[1], output[2], output[3]);
    }
    for (i = 0; i < 256; i++)
    {
        msg_descryptografada[i] = NULL;
    }
    for (i = 0; i < tamanho_texto; i++)
    {
        msg_descryptografada[i] = texto_descriptografado[i];
    }

    num_blocos = 0;
    tamanho_texto = 0;

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
    pr_info("CryptoModule: Mensagem descriptografada!\n");
}
module_init(ebbchar_init);
module_exit(ebbchar_exit);