/* apps/pkeyparam.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2006
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#include <stdio.h>
#include <string.h>
#include "apps.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

const char* pkeyparam_help[] = {
	"-in file        input file",
	"-out file       output file",
	"-text           print parameters as text",
	"-noout          don't output encoded parameters",
#ifndef OPENSSL_NO_ENGINE
	"-engine e       use engine e, possibly a hardware device.",
#endif
	NULL
};
enum options {
	OPT_ERR = -1, OPT_EOF = 0,
	OPT_IN, OPT_OUT, OPT_TEXT, OPT_NOOUT, OPT_ENGINE,
};
static OPTIONS options[] = {
	{ "in", OPT_IN, '<' },
	{ "out", OPT_OUT, '>' },
	{ "text", OPT_TEXT, '-' },
	{ "noout", OPT_NOOUT, '-' },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's' },
#endif
	{ NULL }
};

int pkeyparam_main(int argc, char **argv)
	{
	char *infile=NULL, *outfile=NULL;
	BIO *in=NULL, *out=NULL;
	int text=0, noout=0;
	EVP_PKEY *pkey=NULL;
	int i,ret=1;
	char* prog;
#ifndef OPENSSL_NO_ENGINE
	char *engine=NULL;
#endif

	prog = opt_init(argc, argv, options);
	while ((i = opt_next()) != 0) {
		switch (i) {
		default:
			BIO_printf(bio_err,"%s: Unhandled flag %d\n", prog, i);
		case OPT_ERR:
			BIO_printf(bio_err,"Valid options are:\n");
			printhelp(pkeyparam_help);
			goto end;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile=opt_arg();
			break;
		case OPT_ENGINE:
			engine=opt_arg();
			break;
		case OPT_TEXT:
			text=1;
			break;
		case OPT_NOOUT:
			noout=1;
			break;
		}
		}

#ifndef OPENSSL_NO_ENGINE
        setup_engine(bio_err, engine, 0);
#endif

	in = bio_open_default(infile, "r");
	if (in == NULL)
		goto end;
	out = bio_open_default(outfile, "w");
	if (out == NULL)
		goto end;
	pkey = PEM_read_bio_Parameters(in, NULL);
	if (!pkey)
		{
		BIO_printf(bio_err, "Error reading parameters\n");
		ERR_print_errors(bio_err);
		goto end;
		}

	if (!noout)
		PEM_write_bio_Parameters(out,pkey);

	if (text)
		EVP_PKEY_print_params(out, pkey, 0, NULL);

	ret = 0;

	end:
	EVP_PKEY_free(pkey);
	BIO_free_all(out);
	BIO_free(in);

	return ret;
	}
