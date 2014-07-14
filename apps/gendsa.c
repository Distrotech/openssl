/* apps/gendsa.c */
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

#include <openssl/opensslconf.h>	/* for OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DSA
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define DEFBITS	512

enum options {
	OPT_ERR = -1, OPT_EOF = 0,
	OPT_OUT, OPT_PASSOUT, OPT_ENGINE, OPT_RAND,
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

OPTIONS gendsa_options[] = {
	{ OPT_HELP_STR, 1, '-', "Usage: %s [args] dsaparam-file\n" },
	{ OPT_HELP_STR, 1, '-', "Valid options are:\n" },
	{ "out", OPT_OUT, '>', "Output the key to the specified file" },
	{ "passout", OPT_PASSOUT, 's' },
	{ "rand", OPT_RAND, 's', "Load the file(s) into the random number generator" },
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

int gendsa_main(int argc, char **argv)
	{
	DSA *dsa=NULL;
	int ret=1;
	char *outfile=NULL;
	char *inrand=NULL,*dsaparams=NULL;
	char *passoutarg = NULL, *passout = NULL;
	BIO *out=NULL,*in=NULL;
	const EVP_CIPHER *enc=NULL;
	char *engine=NULL;
	enum options o;
	char* prog;

	prog = opt_init(argc, argv, gendsa_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
bad:
			opt_help(gendsa_options);
			goto end;
		case OPT_OUT:
			outfile= opt_arg();
			break;
		case OPT_PASSOUT:
			passoutarg= opt_arg();
			break;
		case OPT_ENGINE:
			engine= opt_arg();
			break;
		case OPT_RAND:
			inrand= opt_arg();
			break;
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
		}
	}

	if (opt_num_rest() != 1)
		goto bad;
	argv = opt_rest();
	dsaparams = *argv;

#ifndef OPENSSL_NO_ENGINE
        setup_engine(bio_err, engine, 0);
#endif

	if(!app_passwd(bio_err, NULL, passoutarg, NULL, &passout)) {
		BIO_printf(bio_err, "Error getting password\n");
		goto end;
	}


	in = bio_open_default(dsaparams, "r");
	if (in == NULL)
		goto end2;

	if ((dsa=PEM_read_bio_DSAparams(in,NULL,NULL,NULL)) == NULL)
		{
		BIO_printf(bio_err,"unable to load DSA parameter file\n");
		goto end;
		}
	BIO_free(in);
	in = NULL;
		
	out = bio_open_default(outfile, "w");
	if (out == NULL)
		goto end2;

	if (!app_RAND_load_file(NULL, bio_err, 1) && inrand == NULL)
		{
		BIO_printf(bio_err,"warning, not much extra random data, consider using the -rand option\n");
		}
	if (inrand != NULL)
		BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
			app_RAND_load_files(inrand));

	BIO_printf(bio_err,"Generating DSA key, %d bits\n",
							BN_num_bits(dsa->p));
	if (!DSA_generate_key(dsa)) goto end;

	app_RAND_write_file(NULL, bio_err);

	if (!PEM_write_bio_DSAPrivateKey(out,dsa,enc,NULL,0,NULL, passout))
		goto end;
	ret=0;
end:
	if (ret != 0)
		ERR_print_errors(bio_err);
end2:
	if (in != NULL) BIO_free(in);
	if (out != NULL) BIO_free_all(out);
	if (dsa != NULL) DSA_free(dsa);
	if(passout) OPENSSL_free(passout);
	return(ret);
	}
#else /* !OPENSSL_NO_DSA */

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
