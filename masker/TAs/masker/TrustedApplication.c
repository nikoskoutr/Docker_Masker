#include <string.h>
// #include <tee_internal_api.h>
#include "tee_internal_api.h"
#include "tee_logging.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/pk.h"
#include "polarssl/sha256.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

/* UUID must be unique */
SET_TA_PROPERTIES(
    { 0x12345678, 0x8765, 0x4321, { 'M', 'A', 'S', 'K', '0', '0', '0', '2'} }, /* UUID */
        512, /* dataSize */
        255, /* stackSize */
        1, /* singletonInstance */
        1, /* multiSession */
        1) /* instanceKeepAlive */
#endif

#define CMD_GEN_RANDOMS	0
#define CMD_DO_SIGN	1
#define SHA256_DIGEST_LENGTH 32

TEE_Result TA_CreateEntryPoint(void)
{
     OT_LOG(LOG_ERR, "Open Session to TEE");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
     OT_LOG(LOG_ERR, "Destroy Session to TEE");
}


TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
        TEE_Param  params[4], void **sess_ctx)
{

    (void)&params;
    (void)&sess_ctx;
    return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void *sess_ctx)

{
    (void)&sess_ctx;
}
static void printHex(const char *title, const unsigned char *s, int len)
{
	int     n;
	printf("%s:\n", title);
	for (n = 0; n < len; ++n) {
		if ((n % 16) == 0) {
			;//printf("\n%04x", n);
		}
		printf("%02x", s[n]);
	}
	printf("\n");
}

static TEE_Result gen_randoms(uint32_t param_types, TEE_Param params[4])
{
    ctr_drbg_context ctr_drbg;
    entropy_context entropy;
    char * mask = params[0].memref.buffer;
    const char *pers = "aes_generate_key";
    int ret;
    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
        (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n ! ctr_drbg_init returned -0x%04x\n", -ret );
        return 0;
    }

    if( ( ret = ctr_drbg_random( &ctr_drbg, mask, 32 ) ) != 0 )
    {
        printf( " failed\n ! ctr_drbg_random returned -0x%04x\n", -ret );
        return 0;
    }

    return TEE_SUCCESS;
}

static TEE_Result doSign(uint32_t param_types, TEE_Param params[4])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int ret = 0;
    pk_context pk;
    ctr_drbg_context ctr_drbg;
    entropy_context entropy;
    const char *pers = "random_noise";
    unsigned char * data = params[0].memref.buffer;
    int dataLen = params[0].memref.size;
    char *prikey = "prkey.pem";
    unsigned char sign[2048];
    size_t signLen = sizeof(sign);
    size_t olen = 0;

    sha256(data, dataLen, hash, 0); //hashing the message

    /*
     * Read the RSA privatekey
     */
    pk_init( &pk );

    if( ( ret = pk_parse_keyfile( &pk, prikey, "" ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        return 0;
    }

    /* Sign */
    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
        (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n ! ctr_drbg_init returned -0x%04x\n", -ret );
        return 0;
    }

    if( ( ret = pk_encrypt( &pk, hash, SHA256_DIGEST_LENGTH,
                                    sign, &olen, signLen,
                                    ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
       printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
       return 0;
    }

    printHex("Signature", sign, olen);

    return TEE_SUCCESS;
}


TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
            uint32_t param_types, TEE_Param params[4])
{
    (void)&sess_ctx; /* Unused parameter */
    switch (cmd_id) {
    case CMD_GEN_RANDOMS:
        return gen_randoms(param_types, params);
    case CMD_DO_SIGN:
        return doSign(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
