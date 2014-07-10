/* apps/ec.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_EC
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

const char* ec_help[] = {
	"-inform arg     input format - DER or PEM",
	"-outform arg    output format - DER or PEM",
	"-in arg         input file",
	"-passin arg     input file pass phrase source",
	"-out arg        output file",
	"-passout arg    output file pass phrase source",
	"-engine e       use engine e, possibly a hardware device.",
	"-des            encrypt PEM output, instead of 'des' every other ",
				"                 cipher supported by OpenSSL can be used",
	"-text           print the key",
	"-noout          don't print key out",
	"-param_out      print the elliptic curve parameters",
	"-conv_form arg  specifies the point conversion form ",
	"                possible values: compressed",
	"                    uncompressed (default) or hybrid",
	"-param_enc arg  specifies the way the ec parameters are encoded",
	"                 in the asn1 der encoding",
	"                 possible values: named_curve (default) or explicit",
	NULL
};

enum options {
	OPT_ERR = -1, OPT_EOF = 0,
	OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_IN, OPT_OUT,
	OPT_NOOUT, OPT_TEXT, OPT_PARAM_OUT, OPT_PUBIN, OPT_PUBOUT,
	OPT_PASSIN, OPT_PASSOUT, OPT_PARAM_ENC, OPT_CONV_FORM, OPT_CIPHER,
};
static OPTIONS options[] = {
	{ "inform", OPT_INFORM, 'F' },
	{ "outform", OPT_OUTFORM, 'F' },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's' },
#endif
	{ "in", OPT_IN, '<' },
	{ "out", OPT_OUT, '>' },
	{ "noout", OPT_NOOUT, '-' },
	{ "text", OPT_TEXT, '-' },
	{ "param_out", OPT_PARAM_OUT, '-' },
	{ "pubin", OPT_PUBIN, '-' },
	{ "pubout", OPT_PUBOUT, '-' },
	{ "passin", OPT_PASSIN, 's' },
	{ "passout", OPT_PASSOUT, 's' },
	{ "param_enc", OPT_PARAM_ENC, 's' },
	{ "conv_form", OPT_CONV_FORM, 's' },
	{ "", OPT_CIPHER, '-' },
	{ NULL }
};

int ec_main(int argc, char **argv)
{
	int 	ret = 1;
	EC_KEY 	*eckey = NULL;
	const EC_GROUP *group;
	int  i;
	const EVP_CIPHER *enc = NULL;
	BIO 	*in = NULL, *out = NULL;
	int 	informat=FORMAT_PEM, outformat=FORMAT_PEM, text=0, noout=0;
	int  	pubin = 0, pubout = 0, param_out = 0;
	char 	*infile=NULL, *outfile=NULL, *prog, *engine=NULL;
	char 	*passinarg = NULL, *passoutarg = NULL;
	char 	*passin = NULL, *passout = NULL;
	point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
	int	new_form = 0;
	int	asn1_flag = OPENSSL_EC_NAMED_CURVE;
	int 	new_asn1_flag = 0;
	enum options o;

	prog = opt_init(argc, argv, options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
bad:
			BIO_printf(bio_err,"Valid options are:\n");
			printhelp(ec_help);
			goto end;
		case OPT_INFORM:
			opt_format(opt_arg(), 1, &informat);
			break;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUTFORM:
			opt_format(opt_arg(), 1, &outformat);
			break;
		case OPT_OUT:
			outfile= opt_arg();
			break;
		case OPT_NOOUT:
			noout = 1;
			break;
		case OPT_TEXT:
			text = 1;
			break;
		case OPT_PARAM_OUT:
			param_out = 1;
			break;
		case OPT_PUBIN:
			pubin=1;
			break;
		case OPT_PUBOUT:
			pubout=1;
			break;
		case OPT_PASSIN:
			passinarg= opt_arg();
			break;
		case OPT_PASSOUT:
			passoutarg= opt_arg();
			break;
		case OPT_ENGINE:
			engine= opt_arg();
			break;
		case OPT_CIPHER:
			if (!opt_cipher(opt_unknown(), &enc))
				goto bad;
		case OPT_CONV_FORM:
			new_form = 1;
			if (strcmp(*argv, "compressed") == 0)
				form = POINT_CONVERSION_COMPRESSED;
			else if (strcmp(*argv, "uncompressed") == 0)
				form = POINT_CONVERSION_UNCOMPRESSED;
			else if (strcmp(*argv, "hybrid") == 0)
				form = POINT_CONVERSION_HYBRID;
			else
				goto bad;
			break;
		case OPT_PARAM_ENC:
			new_asn1_flag = 1;
			if (strcmp(*argv, "named_curve") == 0)
				asn1_flag = OPENSSL_EC_NAMED_CURVE;
			else if (strcmp(*argv, "explicit") == 0)
				asn1_flag = 0;
			else
				goto bad;
			break;
		}
	}

#ifndef OPENSSL_NO_ENGINE
        setup_engine(bio_err, engine, 0);
#endif

	if(!app_passwd(bio_err, passinarg, passoutarg, &passin, &passout)) 
		{
		BIO_printf(bio_err, "Error getting passwords\n");
		goto end;
		}

	in = bio_open_default(infile, RB(informat));
	if (in == NULL)
		goto end;

	BIO_printf(bio_err, "read EC key\n");
	if (informat == FORMAT_ASN1) 
		{
		if (pubin) 
			eckey = d2i_EC_PUBKEY_bio(in, NULL);
		else 
			eckey = d2i_ECPrivateKey_bio(in, NULL);
		} 
	else
		{
		if (pubin) 
			eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
		else 
			eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, passin);
		} 
	if (eckey == NULL)
		{
		BIO_printf(bio_err,"unable to load Key\n");
		ERR_print_errors(bio_err);
		goto end;
		}

	out = bio_open_default(outfile, WB(outformat));
	if (out == NULL)
		goto end;

	group = EC_KEY_get0_group(eckey);

	if (new_form)
		EC_KEY_set_conv_form(eckey, form);

	if (new_asn1_flag)
		EC_KEY_set_asn1_flag(eckey, asn1_flag);

	if (text) 
		if (!EC_KEY_print(out, eckey, 0))
			{
			perror(outfile);
			ERR_print_errors(bio_err);
			goto end;
			}

	if (noout) 
		{
		ret = 0;
		goto end;
		}

	BIO_printf(bio_err, "writing EC key\n");
	if (outformat == FORMAT_ASN1) 
		{
		if (param_out)
			i = i2d_ECPKParameters_bio(out, group);
		else if (pubin || pubout) 
			i = i2d_EC_PUBKEY_bio(out, eckey);
		else 
			i = i2d_ECPrivateKey_bio(out, eckey);
		} 
	else
		{
		if (param_out)
			i = PEM_write_bio_ECPKParameters(out, group);
		else if (pubin || pubout)
			i = PEM_write_bio_EC_PUBKEY(out, eckey);
		else 
			i = PEM_write_bio_ECPrivateKey(out, eckey, enc,
						NULL, 0, NULL, passout);
		} 

	if (!i)
		{
		BIO_printf(bio_err, "unable to write private key\n");
		ERR_print_errors(bio_err);
		}
	else
		ret=0;
end:
	if (in)
		BIO_free(in);
	if (out)
		BIO_free_all(out);
	if (eckey)
		EC_KEY_free(eckey);
	if (passin)
		OPENSSL_free(passin);
	if (passout)
		OPENSSL_free(passout);
	return(ret);
}
#else /* !OPENSSL_NO_EC */

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
