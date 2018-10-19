/* 	Leonardo Carbonari        	13126578
#	Matheus Franceschini        	13129788
#	Pedro Tortella            	13035555
#	Tales Falcão            	13146394
#	Diogo Esteves Furtado     	15153927
#	Kaíque Ferreira Fávero    	15118698
*/
#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/slab.h>            //kmalloc
#include <linux/crypto.h>
#include <crypto/sha.h>
#include <crypto/internal/hash.h>
#include <linux/scatterlist.h>
#include <asm/uaccess.h>          // Required for the copy to user function
#define  DEVICE_NAME "crypto"    ///< The device will appear at /dev/crypto using this value
#define  CLASS_NAME  "cryp"        ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("Grupo SOB");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Crypto driver");  ///< The description -- see modinfo
MODULE_VERSION("0.1");            ///< A version number to inform users

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  cryptocharClass  = NULL; ///< The device-driver class struct pointer
static struct device* cryptocharDevice = NULL; ///< The device-driver device struct pointer

int size = 0;
char *key;
char *encrypted;
char *decrypted;
unsigned char *sha1res;
char *message;

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "key");

// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations fops = {
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
static int __init crypto_init(void){
   printk(KERN_INFO "Initializing Crypto with key: %s\n", key);
   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "Crypto failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "Crypto: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   cryptocharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(cryptocharClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(cryptocharClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "Crypto: device class registered correctly\n");

   // Register the device driver
   cryptocharDevice = device_create(cryptocharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(cryptocharDevice)){               // Clean up if there is an error
      class_destroy(cryptocharClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(cryptocharDevice);
   }
   printk(KERN_INFO "Crypto: device class created correctly\n"); // Made it! device was initialized
   return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit crypto_exit(void){
   device_destroy(cryptocharClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(cryptocharClass);                          // unregister the device class
   class_destroy(cryptocharClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "Crypto: Goodbye from the LKM!\n");
}

/** @brief The device open function that is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "Crypto: Device has been opened %d time(s)\n", numberOpens);
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
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "Crypto: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "Crypto: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}
  

void hash(char *in) {
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

void encrypt(char *in) {
      int i,count,div,modd;
      struct crypto_cipher *tfm;
      in = strim(in);
      div=strlen(in)/16;
      modd=strlen(in)%16;
      if(modd>0) {
            div++; 
      }
      count=div;
      size = strlen(in);
      encrypted = kmalloc(size * count, GFP_ATOMIC);

      tfm = crypto_alloc_cipher("aes", 0, 16); 
      crypto_cipher_setkey(tfm,key,16);  
      for(i=0;i<count;i++) {  
            char *c = kmalloc(size, GFP_ATOMIC);
            crypto_cipher_encrypt_one(tfm,c,in);    
            if(i == 0) {
                  strcpy(encrypted, c);
            } else {
                  strcat(encrypted, c);
            }
            in+=16;  
      }
        
      crypto_free_cipher(tfm);  
}
  
void decrypt(void) {  
      int i,count,div,modd;
      struct crypto_cipher *tfm;
      
      div=size/16;
      modd=size%16;
      if(modd>0) {
            div++; 
      }
      count=div;

      decrypted = kmalloc(size * count, GFP_ATOMIC);
      tfm = crypto_alloc_cipher("aes", 0, 16);  
      crypto_cipher_setkey(tfm,key,16);

      for(i=0;i<count;i++) {  
            char *c = kmalloc(size, GFP_ATOMIC);
            crypto_cipher_decrypt_one(tfm,c,encrypted); 
            if(i == 0) {
                  strcpy(decrypted, c);
            } else {
                  strcat(decrypted, c);
            }
            encrypted+=16;    
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
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   char opcao = *buffer;
   char *src = kmalloc(strlen(buffer), GFP_ATOMIC);

   switch(opcao) {
      case 'c':
            strcpy(src, buffer);
            strsep(&src, " ");
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
    
   size_of_message = strlen(message);                 // store the length of the stored message
   return len;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "Crypto: Device successfully closed\n");
   return 0;
}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(crypto_init);
module_exit(crypto_exit);
