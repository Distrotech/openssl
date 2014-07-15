/* apps/gendh.c */
/* obsoleted by dhparam.c */
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

#ifndef OPENSSL_NO_DH
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define DEFBITS	512

static int dh_cb(int p, int n, BN_GENCB *cb);

enum options {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_OUT, OPT_2, OPT_5, OPT_ENGINE, OPT_RAND
};

OPTIONS gendh_options[] = {
	{ OPT_HELP_STR, 1, '-', "Usage: %s [options] numbits\n" },
	{ OPT_HELP_STR, 1, '-', "Valid options are:\n" },
	{ "help", OPT_HELP, '-', "Display this summary" },
	{ "out", OPT_OUT, '>', "Output the key to specified file" },
	{ "2", OPT_2, '-', "Use 2 as the generator value" },
	{ "5", OPT_5, '-', "Use 5 as the generator value" },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device" },
#endif
	{ "rand", OPT_RAND, 's', "Load the file(s) into the random number generator" },
	{ NULL }
};

int gendh_main(int argc, char **argv)
	{
	BN_GENCB cb;
	DH *dh=NULL;
	int i,ret=1,num=DEFBITS;
	int g=2;
	char *outfile=NULL;
	char *inrand=NULL;
	BIO *out=NULL;
	char* prog;
#ifndef OPENSSL_NO_ENGINE
	char *engine=NULL;
#endif

	BN_GENCB_set(&cb, dh_cb, bio_err);
	prog = opt_init(argc, argv, gendh_options);
	while ((i = opt_next()) != OPT_EOF) {
		switch (i) {
		case OPT_EOF:
		case OPT_ERR:
		case OPT_HELP:
err:
			opt_help(gendh_options);
			goto end;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_2:
			g=2;
			break;
		case OPT_5:
			g=5;
			break;
		case OPT_ENGINE:
			engine= opt_arg();
			break;
		case OPT_RAND:
			inrand = opt_arg();
			break;
		}
	}
	argv = opt_rest();
	if (argv[0] != NULL && (sscanf(*argv,"%d",&num) == 0 || num < 0))
		goto err;

#ifndef OPENSSL_NO_ENGINE
        setup_engine(bio_err, engine, 0);
#endif

	out = bio_open_default(outfile, "w");
	if (out == NULL)
		goto end;

	if (!app_RAND_load_file(NULL, bio_err, 1) && inrand == NULL)
		{
		BIO_printf(bio_err,"warning, not much extra random data, consider using the -rand option\n");
		}
	if (inrand != NULL)
		BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
			app_RAND_load_files(inrand));

	BIO_printf(bio_err,"Generating DH parameters, %d bit long safe prime, generator %d\n",num,g);
	BIO_printf(bio_err,"This is going to take some time\n");

	if ((dh = DH_new()) == NULL || !DH_generate_parameters_ex(dh, num, g, &cb))
		goto end;
		
	app_RAND_write_file(NULL, bio_err);

	if (!PEM_write_bio_DHparams(out,dh))
		goto end;
	ret=0;
end:
	if (ret != 0)
		ERR_print_errors(bio_err);
	if (out != NULL) BIO_free_all(out);
	if (dh != NULL) DH_free(dh);
	return(ret);
	}

static int dh_cb(int p, int n, BN_GENCB *cb)
	{
	char c='*';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	BIO_write(cb->arg,&c,1);
	(void)BIO_flush(cb->arg);
	return 1;
	}
#else /* !OPENSSL_NO_DH */

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
