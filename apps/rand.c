/* apps/rand.c */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#include "apps.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>


const char *rand_help[] = {
	"-out file        write to file",
	"-rand file...    seed PRNG from files",
	"-base64          base64 encode output",
	"-hex             hex encode output",
#ifndef OPENSSL_NO_ENGINE
	"-engine e        use engine e, possibly a hardware device",
#endif
	NULL
};
enum options {
	OPT_ERR = -1, OPT_EOF = 0,
	OPT_OUT, OPT_ENGINE, OPT_RAND, OPT_BASE64, OPT_HEX
};
static OPTIONS options[] = {
	{ "out", OPT_OUT, '>' },
	{ "engine", OPT_ENGINE, 's' },
	{ "rand", OPT_RAND, 's' },
	{ "base64", OPT_BASE64, '-' },
	{ "hex", OPT_HEX, '-' },
	{ NULL }
};


int rand_main(int argc, char **argv)
	{
	int i, r, ret = 1;
	char *outfile = NULL;
	char *inrand = NULL;
	int base64 = 0;
	int hex = 0;
	BIO *out = NULL;
	int num = -1;
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
bad:
			BIO_printf(bio_err,"Usage: %s [flags] num\n",
					prog);
			BIO_printf(bio_err,"Valid options are:\n");
			printhelp(rand_help);
			goto end;
		case OPT_OUT:
			outfile=opt_arg();
			break;
		case OPT_ENGINE:
			engine = opt_arg();
			break;
		case OPT_RAND:
			inrand = opt_arg();
			break;
		case OPT_BASE64:
			base64=1;
			break;
		case OPT_HEX:
			hex=1;
			break;
		}
	}
	if (opt_num_rest() != 1 || (hex && base64))
		goto bad;
	argv = opt_rest();
	if (sscanf(argv[0], "%d", &num) != 1 || num < 0)
		goto bad;

#ifndef OPENSSL_NO_ENGINE
        setup_engine(bio_err, engine, 0);
#endif

	app_RAND_load_file(NULL, bio_err, (inrand != NULL));
	if (inrand != NULL)
		BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
			app_RAND_load_files(inrand));

	out = bio_open_default(outfile, "w");
	if (out == NULL)
		goto end;

	if (base64)
		{
		BIO *b64 = BIO_new(BIO_f_base64());
		if (b64 == NULL)
			goto end;
		out = BIO_push(b64, out);
		}
	
	while (num > 0) 
		{
		unsigned char buf[4096];
		int chunk;

		chunk = num;
		if (chunk > (int)sizeof(buf))
			chunk = sizeof buf;
		r = RAND_bytes(buf, chunk);
		if (r <= 0)
			goto end;
		if (!hex) 
			BIO_write(out, buf, chunk);
		else
			{
			for (i = 0; i < chunk; i++)
				BIO_printf(out, "%02x", buf[i]);
			}
		num -= chunk;
		}
	if (hex)
		BIO_puts(out, "\n");
	(void)BIO_flush(out);

	app_RAND_write_file(NULL, bio_err);
	ret = 0;
	
end:
	if (out)
		BIO_free_all(out);
	return(ret);
	}
