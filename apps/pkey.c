/* apps/pkey.c */
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

enum options {
	OPT_ERR = -1, OPT_EOF = 0,
	OPT_INFORM, OPT_OUTFORM, OPT_PASSIN, OPT_PASSOUT, OPT_ENGINE,
	OPT_IN, OPT_OUT, OPT_PUBIN, OPT_PUBOUT, OPT_TEXT_PUB,
	OPT_TEXT, OPT_NOOUT, OPT_MD,
};

OPTIONS pkey_options[] = {
	{ "inform", OPT_INFORM, 'F', "Input format (DER or PEM)" },
	{ "outform", OPT_OUTFORM, 'F', "Output format (DER or PEM)" },
	{ "passin", OPT_PASSIN, 's', "Input file pass phrase source" },
	{ "passout", OPT_PASSOUT, 's', "Output file pass phrase source" },
	{ "in", OPT_IN, '<', "Input file" },
	{ "out", OPT_OUT, '>', "Output file" },
	{ "pubin", OPT_PUBIN, '-', "Read public key from input (default is private key)" },
	{ "pubout", OPT_PUBOUT, '-', "Output public key, not private" },
	{ "text_pub", OPT_TEXT_PUB, '-', "Only output public key components" },
	{ "text", OPT_TEXT, '-', "Output in plaintext as well" },
	{ "noout", OPT_NOOUT, '-', "Don't output the key" },
	{ "", OPT_MD, '-', "Any supported cipher" },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device" },
#endif
	{ NULL }
};


int pkey_main(int argc, char **argv)
	{
	ENGINE *e = NULL;
	char *infile = NULL, *outfile = NULL;
	char *passinarg = NULL, *passoutarg = NULL;
	BIO *in = NULL, *out = NULL;
	const EVP_CIPHER *cipher = NULL;
	int informat=FORMAT_PEM, outformat=FORMAT_PEM;
	int pubin = 0, pubout = 0, pubtext = 0, text = 0, noout = 0;
	EVP_PKEY *pkey=NULL;
	char *passin = NULL, *passout = NULL;
	int ret = 1;
	enum options o;
	char* prog, *engine=NULL;

	prog = opt_init(argc, argv, pkey_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
bad:
			opt_help(pkey_options);
			goto end;
		case OPT_INFORM:
			opt_format(opt_arg(), 1, &informat);
			break;
		case OPT_OUTFORM:
			opt_format(opt_arg(), 1, &outformat);
			break;
		case OPT_PASSIN:
			passinarg = opt_arg();
			break;
		case OPT_PASSOUT:
			passoutarg = opt_arg();
			break;
		case OPT_ENGINE:
			engine = opt_arg();
			break;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_PUBIN:
			pubin=pubout=pubtext=1;
			break;
		case OPT_PUBOUT:
			pubout=1;
			break;
		case OPT_TEXT_PUB:
			pubtext=text=1;
			break;
		case OPT_TEXT:
			text=1;
			break;
		case OPT_NOOUT:
			noout=1;
			break;
		case OPT_MD:
			if (!opt_cipher(opt_unknown(), &cipher))
				goto bad;
		}
	}


#ifndef OPENSSL_NO_ENGINE
        e = setup_engine(bio_err, engine, 0);
#endif

	if (!app_passwd(bio_err, passinarg, passoutarg, &passin, &passout))
		{
		BIO_printf(bio_err, "Error getting passwords\n");
		goto end;
		}

	out = bio_open_default(outfile, "wb");
	if (out == NULL)
		goto end;

	if (pubin)
		pkey = load_pubkey(bio_err, infile, informat, 1,
			passin, e, "Public Key");
	else
		pkey = load_key(bio_err, infile, informat, 1,
			passin, e, "key");
	if (!pkey)
		goto end;

	if (!noout)
		{
		if (outformat == FORMAT_PEM) 
			{
			if (pubout)
				PEM_write_bio_PUBKEY(out,pkey);
			else
				PEM_write_bio_PrivateKey(out, pkey, cipher,
							NULL, 0, NULL, passout);
			}
		else if (outformat == FORMAT_ASN1)
			{
			if (pubout)
				i2d_PUBKEY_bio(out, pkey);
			else
				i2d_PrivateKey_bio(out, pkey);
			}
		else
			{
			BIO_printf(bio_err, "Bad format specified for key\n");
			goto end;
			}

		}

	if (text)
		{
		if (pubtext)
			EVP_PKEY_print_public(out, pkey, 0, NULL);
		else
			EVP_PKEY_print_private(out, pkey, 0, NULL);
		}

	ret = 0;

	end:
	EVP_PKEY_free(pkey);
	BIO_free_all(out);
	BIO_free(in);
	if (passin)
		OPENSSL_free(passin);
	if (passout)
		OPENSSL_free(passout);

	return ret;
	}
