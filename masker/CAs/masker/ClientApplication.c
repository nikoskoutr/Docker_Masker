#include <string.h> /* memset */

#include <stdio.h>
#include <err.h>
#include <tee_client_api.h>
static const TEEC_UUID uuid = {
    0x12345678, 0x8765, 0x4321, { 'M', 'A', 'S', 'K', '0', '0', '0', '2'}
};

/* The TAFs ID implemented in this TA */
#define CMD_GEN_RANDOMS	0
#define CMD_DO_SIGN	1


int main(int argc, char *argv[])
{
        TEEC_Result res;
        TEEC_Context ctx;
        TEEC_Session sess;
        TEEC_Operation op;
        uint32_t err_origin;

        /* Initialize a context connecting us to the TEE */
        res = TEEC_InitializeContext(NULL, &ctx);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

        /*
         * Open a session to the TA
         */
        res = TEEC_OpenSession(&ctx, &sess, &uuid,
                               TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
                        res, err_origin);

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,TEEC_NONE, TEEC_NONE);

        int i, j;
        unsigned char gened_mask[32];
        char *privkey = "prkey.pem";
        unsigned char *data;
        unsigned int dataLen;
        unsigned char sign[256];
        char dt_to_sign[18]="";
        char *sm_id;
        char *sm_seq;
        int consumption;

            /* there should be at least 1 arg (consumption) for correct execution */
            if ( argc < 2 )
            {
                /* We print argv[0] assuming it is the program name */
                printf( "Usage: %s consumption id seq\n\
                consumption: consumption to be masked, range 0-40000, required\n\
                id: smart meter ID, 10 numerical digits, optional\n\
                seq:  mask sequence number, 3 numerical digits, optional\n", argv[0] );
            }
            else
            {
                consumption=atoi(argv[1]);

                if ( argc > 2 )
                    sm_id = argv[2];
                else
                    sm_id = "1520160001";

                if ( argc > 3 )
                    sm_seq = argv[3];
                else
                    sm_seq = "211";
                    
                op.params[0].tmpref.buffer = gened_mask;
                op.params[0].tmpref.size = 32;

                do {
                    
                    res = TEEC_InvokeCommand(&sess, CMD_GEN_RANDOMS, &op,
                                             &err_origin);
                    if (res != TEEC_SUCCESS){
                            errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

                    
                        for(j = 0; (i < 40960 || i > 65535) && j<32 ;j=j+2)
                        {
                            i = (int)gened_mask[j] << 8 | (int)gened_mask[j+1];
                            i = i + consumption;
                        }
                    }
                    else{
                        printf("Mask generation failed\n");
			        }
                } while (i < 40960 || i > 65535);

                char buf[5]="";
                sprintf(buf, "%d", i);

                strcpy(dt_to_sign, sm_id); // smart meter ID
                strncat(dt_to_sign, buf, 5); // masked reading
                strncat(dt_to_sign, sm_seq, 3); // seq No

                printf("data to sign: %s\n", dt_to_sign);

                data = (unsigned char *)dt_to_sign;
                dataLen = strlen(dt_to_sign);

                op.params[0].tmpref.buffer = data;
                op.params[0].tmpref.size = dataLen;

                res = TEEC_InvokeCommand(&sess, CMD_DO_SIGN, &op,
                                         &err_origin);
                if (res != TEEC_SUCCESS)
                        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
                                res, err_origin);


        TEEC_CloseSession(&sess);

        TEEC_FinalizeContext(&ctx);

        return 0;
	}
}



