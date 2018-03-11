#ifndef __LEAK_HELPER_H
# define __LEAK_HELPER_H

# define LEEK_ADDRESS_LEN              16
# define LEEK_RAWADDR_LEN              10
# define LEEK_CACHELINE_SZ             64 /* bytes */

/* Number of bits per base32 character */
# define LEEK_RAWADDR_CHAR_BITS        5

/* This value ensures that our exponent will always be 4 bytes wide
 * We may consider starting at RSA_F4 instead and handle 3 bytes exponent. */
# define LEEK_RSA_E_SIZE               4 /* bytes */
# define LEEK_RSA_E_START              0x00800001u
/* This limit allows for 8 parallel computations */
# define LEEK_RSA_E_LIMIT              0x7FFFFFFFu
# define LEEK_RSA_KEYSIZE              1024
# define LEEK_RSA_PRIME_SIZE           (LEEK_RSA_KEYSIZE / 2)

/* Compiler short flags for functions and structures */
# define __packed                      __attribute__((packed))
# define __flatten                     __attribute__((flatten))
# define __hot                         __attribute__((hot))

/* Help compiler generating more optimized code for some expected branches */
# define likely(x)                     __builtin_expect(!!(x), 1)
# define unlikely(x)                   __builtin_expect(!!(x), 0)

/* Create result directory if needed */
int leek_result_dir_init(void);

/* OpenSSL locks (required for MT operations) */
int leek_openssl_init(void);

/* Corresponding destructor for these locks and cache cleanup */
void leek_openssl_exit(void);


#endif /* !__LEAK_HELPER_H */
