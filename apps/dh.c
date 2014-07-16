/* apps/dh.c */
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

#include <openssl/opensslconf.h>	/* for OPENSSL_NO_DH */
#ifndef OPENSSL_NO_DH
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

enum options {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_ENGINE,
	OPT_CHECK, OPT_TEXT, OPT_C, OPT_NOOUT
};

OPTIONS dh_options[] = {
	{ "help", OPT_HELP, '-', "Display this summary" },
	{ "inform", OPT_INFORM, 'F', "Input format - one of DER PEM" },
	{ "outform", OPT_OUTFORM, 'F', "Output format - one of DER PEM" },
	{ "in", OPT_IN, '<', "Input file" },
	{ "out", OPT_OUT, '>', "Output file" },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device" },
#endif
	{ "check", OPT_CHECK, '-', "Check the DH parameters" },
	{ "text", OPT_TEXT, '-', "Print a text form of the DH parameters" },
	{ "C", OPT_C, '-', "Output C code" },
	{ "noout", OPT_NOOUT, '-', "Oo output" },
	{ NULL }
};

int dh_main(int argc, char **argv)
	{
	DH *dh=NULL;
	BIO *in=NULL, *out=NULL;
	int informat=FORMAT_PEM, outformat=FORMAT_PEM, check=0, noout=0, C=0;
	int i, text=0, ret=1;
	char *infile=NULL, *outfile=NULL, *prog, *engine=NULL;
	enum options o;

	prog = opt_init(argc, argv, dh_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(dh_options);
			goto end;
		case OPT_INFORM:
			opt_format(opt_arg(), 1, &informat);
			break;
		case OPT_OUTFORM:
			opt_format(opt_arg(), 1, &outformat);
			break;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile= opt_arg();
			break;
		case OPT_ENGINE:
			engine = opt_arg();
			break;
		case OPT_CHECK:
			check=1;
			break;
		case OPT_TEXT:
			text=1;
			break;
		case OPT_C:
			C=1;
			break;
		case OPT_NOOUT:
			noout=1;
			break;
		}
	}

#ifndef OPENSSL_NO_ENGINE
        setup_engine(bio_err, engine, 0);
#endif

	in = bio_open_default(infile, RB(informat));
	if (in == NULL)
		goto end;
	out = bio_open_default(outfile, WB(outformat));
	if (out == NULL)
		goto end;

	if	(informat == FORMAT_ASN1)
		dh=d2i_DHparams_bio(in,NULL);
	else if (informat == FORMAT_PEM)
		dh=PEM_read_bio_DHparams(in,NULL,NULL,NULL);
	if (dh == NULL)
		{
		BIO_printf(bio_err,"unable to load DH parameters\n");
		ERR_print_errors(bio_err);
		goto end;
		}

	if (text)
		{
		DHparams_print(out,dh);
#if 0
		printf("p=");
		BN_print(stdout,dh->p);
		printf("\ng=");
		BN_print(stdout,dh->g);
		printf("\n");
		if (dh->length != 0)
			printf("recommended private length=%ld\n",dh->length);
#endif
		}
	
	if (check)
		{
		if (!DH_check(dh,&i))
			{
			ERR_print_errors(bio_err);
			goto end;
			}
		if (i & DH_CHECK_P_NOT_PRIME)
			printf("p value is not prime\n");
		if (i & DH_CHECK_P_NOT_SAFE_PRIME)
			printf("p value is not a safe prime\n");
		if (i & DH_UNABLE_TO_CHECK_GENERATOR)
			printf("unable to check the generator value\n");
		if (i & DH_NOT_SUITABLE_GENERATOR)
			printf("the g value is not a generator\n");
		if (i == 0)
			printf("DH parameters appear to be ok.\n");
		}
	if (C)
		{
		unsigned char *data;
		int len,l,bits;

		len=BN_num_bytes(dh->p);
		bits=BN_num_bits(dh->p);
		data=(unsigned char *)OPENSSL_malloc(len);
		if (data == NULL)
			{
			perror("OPENSSL_malloc");
			goto end;
			}
		l=BN_bn2bin(dh->p,data);
		printf("static unsigned char dh%d_p[]={",bits);
		for (i=0; i<l; i++)
			{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
			}
		printf("\n\t};\n");

		l=BN_bn2bin(dh->g,data);
		printf("static unsigned char dh%d_g[]={",bits);
		for (i=0; i<l; i++)
			{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
			}
		printf("\n\t};\n\n");

		printf("DH *get_dh%d()\n\t{\n",bits);
		printf("\tDH *dh;\n\n");
		printf("\tif ((dh=DH_new()) == NULL) return(NULL);\n");
		printf("\tdh->p=BN_bin2bn(dh%d_p,sizeof(dh%d_p),NULL);\n",
			bits,bits);
		printf("\tdh->g=BN_bin2bn(dh%d_g,sizeof(dh%d_g),NULL);\n",
			bits,bits);
		printf("\tif ((dh->p == NULL) || (dh->g == NULL))\n");
		printf("\t\treturn(NULL);\n");
		printf("\treturn(dh);\n\t}\n");
		OPENSSL_free(data);
		}


	if (!noout)
		{
		if 	(outformat == FORMAT_ASN1)
			i=i2d_DHparams_bio(out,dh);
		else
			i=PEM_write_bio_DHparams(out,dh);
		if (!i)
			{
			BIO_printf(bio_err,"unable to write DH parameters\n");
			ERR_print_errors(bio_err);
			goto end;
			}
		}
	ret=0;
end:
	if (in != NULL) BIO_free_all(in);
	if (out != NULL) BIO_free_all(out);
	if (dh != NULL) DH_free(dh);
	return(ret);
	}
#else /* !OPENSSL_NO_DH */

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
