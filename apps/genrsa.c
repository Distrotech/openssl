/* apps/genrsa.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <openssl/opensslconf.h>
/* Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code */
#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#ifndef OPENSSL_NO_RSA
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define DEFBITS	1024

static int genrsa_cb(int p, int n, BN_GENCB *cb);

enum options {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_3, OPT_F4, OPT_NON_FIPS_ALLOW, OPT_ENGINE,
	OPT_OUT, OPT_RAND, OPT_PASSOUT,
#ifndef OPENSSL_NO_DES
	OPT_DES, OPT_DES3,
#endif
#ifndef OPENSSL_NO_IDEA
	OPT_IDEA,
#endif
#ifndef OPENSSL_NO_SEED
	OPT_SEED,
#endif
#ifndef OPENSSL_NO_AES
	OPT_AES128, OPT_AES192, OPT_AES256,
#endif
#ifndef OPENSSL_NO_CAMELLIA
	OPT_CAMELLIA128, OPT_CAMELLIA192, OPT_CAMELLIA256,
#endif
};

OPTIONS genrsa_options[] = {
	{ "help", OPT_HELP, '-', "Display this summary" },
	{ "3", OPT_3, '-', "Use 3 for the E value" },
	{ "F4", OPT_F4, '-', "Use F4 (0x10001) for the E value" },
	{ "f4", OPT_F4, '-', "Use F4 (0x10001) for the E value" },
	{ "non-fips-allow", OPT_NON_FIPS_ALLOW, '-' },
	{ "out", OPT_OUT, 's', "Output the key to specified file" },
	{ "rand", OPT_RAND, 's', "Load the file(s) into the random number generator" },
	{ "passout", OPT_PASSOUT, 's', "Output file pass phrase source" },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device" },
#endif
#ifndef OPENSSL_NO_DES
	{ "des", OPT_DES, '-', "Encrypt the output with CBC DES" },
	{ "des3", OPT_DES3, '-', "Encrypt the output with CBC 3DES" },
#endif
#ifndef OPENSSL_NO_IDEA
	{ "idea", OPT_IDEA, '-', "Encrypt the output with CBC IDEA" },
#endif
#ifndef OPENSSL_NO_SEED
	{ "seed", OPT_SEED, '-', "Encrypt key output with CBC seed" },
#endif
#ifndef OPENSSL_NO_AES
	{ "aes128", OPT_AES128, '-', "Encrypt the output with CBC AES 128" },
	{ "aes192", OPT_AES192, '-', "Encrypt the output with CBC AES 192" },
	{ "aes256", OPT_AES256, '-', "Encrypt the output with CBC AES 256" },
#endif
#ifndef OPENSSL_NO_CAMELLIA
	{ "camellia128", OPT_CAMELLIA128, '-', "Encrypt the output with CBC camellia 128" },
	{ "camellia192", OPT_CAMELLIA192, '-', "Encrypt the output with CBC camellia 192" },
	{ "camellia256", OPT_CAMELLIA256, '-', "Encrypt the output with CBC camellia 256" },
#endif
	{ NULL }
};

int genrsa_main(int argc, char **argv)
	{
	BN_GENCB cb;
	ENGINE *e=NULL;
	BIGNUM *bn=BN_new();
	BIO *out=NULL;
	RSA *rsa=NULL;
	const EVP_CIPHER *enc=NULL;
	int ret=1, non_fips_allow=0, i, num=DEFBITS;
	long l;
	unsigned long f4=RSA_F4;
	char *outfile=NULL, *passoutarg=NULL, *passout=NULL;
	char *engine=NULL, *inrand=NULL, *prog;
	enum options o;

	if(!bn) goto err;

	BN_GENCB_set(&cb, genrsa_cb, bio_err);

	prog = opt_init(argc, argv, genrsa_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
		case OPT_HELP:
			opt_help(genrsa_options);
			goto err;
		case OPT_3:
			f4=3;
			break;
		case OPT_F4:
			f4=RSA_F4;
			break;
		case OPT_NON_FIPS_ALLOW:
			non_fips_allow = 1;
			break;
		case OPT_OUT:
			outfile= opt_arg();
		case OPT_ENGINE:
			engine= opt_arg();
			break;
		case OPT_RAND:
			inrand= opt_arg();
			break;
		case OPT_PASSOUT:
			passoutarg= opt_arg();
			break;
#ifndef OPENSSL_NO_DES
		case OPT_DES:
			enc=EVP_des_cbc();
			break;
		case OPT_DES3:
			enc=EVP_des_ede3_cbc();
			break;
#endif
#ifndef OPENSSL_NO_IDEA
		case OPT_IDEA:
			enc=EVP_idea_cbc();
			break;
#endif
#ifndef OPENSSL_NO_SEED
		case OPT_SEED:
			enc=EVP_seed_cbc();
			break;
#endif
#ifndef OPENSSL_NO_AES
		case OPT_AES128:
			enc=EVP_aes_128_cbc();
			break;
		case OPT_AES192:
			enc=EVP_aes_192_cbc();
			break;
		case OPT_AES256:
			enc=EVP_aes_256_cbc();
			break;
#endif
#ifndef OPENSSL_NO_CAMELLIA
		case OPT_CAMELLIA128:
			enc=EVP_camellia_128_cbc();
			break;
		case OPT_CAMELLIA192:
			enc=EVP_camellia_192_cbc();
			break;
		case OPT_CAMELLIA256:
			enc=EVP_camellia_256_cbc();
			break;
#endif
		}
	}
	argv = opt_rest();
	if (argv[0] && (!opt_int(argv[0], &num) || num <= 0))
		goto err;

	if(!app_passwd(bio_err, NULL, passoutarg, NULL, &passout)) {
		BIO_printf(bio_err, "Error getting password\n");
		goto err;
	}

#ifndef OPENSSL_NO_ENGINE
        e = setup_engine(bio_err, engine, 0);
#endif

	out = bio_open_default(outfile, "w");
	if (out == NULL)
		goto err;

	if (!app_RAND_load_file(NULL, bio_err, 1) && inrand == NULL
		&& !RAND_status())
		{
		BIO_printf(bio_err,"warning, not much extra random data, consider using the -rand option\n");
		}
	if (inrand != NULL)
		BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
			app_RAND_load_files(inrand));

	BIO_printf(bio_err,"Generating RSA private key, %d bit long modulus\n",
		num);
#ifdef OPENSSL_NO_ENGINE
	rsa = RSA_new();
#else
	rsa = RSA_new_method(e);
#endif
	if (!rsa)
		goto err;

	if (non_fips_allow)
		rsa->flags |= RSA_FLAG_NON_FIPS_ALLOW;

	if(!BN_set_word(bn, f4) || !RSA_generate_key_ex(rsa, num, bn, &cb))
		goto err;
		
	app_RAND_write_file(NULL, bio_err);

	/* We need to do the following for when the base number size is <
	 * long, esp windows 3.1 :-(. */
	l=0L;
	for (i=0; i<rsa->e->top; i++)
		{
#ifndef SIXTY_FOUR_BIT
		l<<=BN_BITS4;
		l<<=BN_BITS4;
#endif
		l+=rsa->e->d[i];
		}
	BIO_printf(bio_err,"e is %ld (0x%lX)\n",l,l);
	{
	PW_CB_DATA cb_data;
	cb_data.password = passout;
	cb_data.prompt_info = outfile;
	if (!PEM_write_bio_RSAPrivateKey(out,rsa,enc,NULL,0,
		(pem_password_cb *)password_callback,&cb_data))
		goto err;
	}

	ret=0;
err:
	if (bn) BN_free(bn);
	if (rsa) RSA_free(rsa);
	if (out) BIO_free_all(out);
	if(passout) OPENSSL_free(passout);
	if (ret != 0)
		ERR_print_errors(bio_err);
	return(ret);
	}

static int genrsa_cb(int p, int n, BN_GENCB *cb)
	{
	char c='*';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	BIO_write(cb->arg,&c,1);
	(void)BIO_flush(cb->arg);
#ifdef LINT
	p=n;
#endif
	return 1;
	}
#else /* !OPENSSL_NO_RSA */

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
