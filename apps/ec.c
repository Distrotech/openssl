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

int ec_main(int argc, char **argv)
{
	int 	ret = 1;
	EC_KEY 	*eckey = NULL;
	const EC_GROUP *group;
	int 	i, badops = 0;
	const EVP_CIPHER *enc = NULL;
	BIO 	*in = NULL, *out = NULL;
	int 	informat, outformat, text=0, noout=0;
	int  	pubin = 0, pubout = 0, param_out = 0;
	char 	*infile, *outfile, *prog, *engine;
	char 	*passargin = NULL, *passargout = NULL;
	char 	*passin = NULL, *passout = NULL;
	point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
	int	new_form = 0;
	int	asn1_flag = OPENSSL_EC_NAMED_CURVE;
	int 	new_asn1_flag = 0;

	engine = NULL;
	infile = NULL;
	outfile = NULL;
	informat = FORMAT_PEM;
	outformat = FORMAT_PEM;

	prog = argv[0];
	argc--;
	argv++;
	while (argc >= 1)
		{
		if (strcmp(*argv,"-inform") == 0)
			{
			if (--argc < 1) goto bad;
			informat=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-outform") == 0)
			{
			if (--argc < 1) goto bad;
			outformat=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-in") == 0)
			{
			if (--argc < 1) goto bad;
			infile= *(++argv);
			}
		else if (strcmp(*argv,"-out") == 0)
			{
			if (--argc < 1) goto bad;
			outfile= *(++argv);
			}
		else if (strcmp(*argv,"-passin") == 0)
			{
			if (--argc < 1) goto bad;
			passargin= *(++argv);
			}
		else if (strcmp(*argv,"-passout") == 0)
			{
			if (--argc < 1) goto bad;
			passargout= *(++argv);
			}
		else if (strcmp(*argv, "-engine") == 0)
			{
			if (--argc < 1) goto bad;
			engine= *(++argv);
			}
		else if (strcmp(*argv, "-noout") == 0)
			noout = 1;
		else if (strcmp(*argv, "-text") == 0)
			text = 1;
		else if (strcmp(*argv, "-conv_form") == 0)
			{
			if (--argc < 1)
				goto bad;
			++argv;
			new_form = 1;
			if (strcmp(*argv, "compressed") == 0)
				form = POINT_CONVERSION_COMPRESSED;
			else if (strcmp(*argv, "uncompressed") == 0)
				form = POINT_CONVERSION_UNCOMPRESSED;
			else if (strcmp(*argv, "hybrid") == 0)
				form = POINT_CONVERSION_HYBRID;
			else
				goto bad;
			}
		else if (strcmp(*argv, "-param_enc") == 0)
			{
			if (--argc < 1)
				goto bad;
			++argv;
			new_asn1_flag = 1;
			if (strcmp(*argv, "named_curve") == 0)
				asn1_flag = OPENSSL_EC_NAMED_CURVE;
			else if (strcmp(*argv, "explicit") == 0)
				asn1_flag = 0;
			else
				goto bad;
			}
		else if (strcmp(*argv, "-param_out") == 0)
			param_out = 1;
		else if (strcmp(*argv, "-pubin") == 0)
			pubin=1;
		else if (strcmp(*argv, "-pubout") == 0)
			pubout=1;
		else if ((enc=EVP_get_cipherbyname(&(argv[0][1]))) == NULL)
			{
			BIO_printf(bio_err, "unknown option %s\n", *argv);
			badops=1;
			break;
			}
		argc--;
		argv++;
		}

	if (badops)
		{
bad:
		BIO_printf(bio_err, "%s [options] <infile >outfile\n", prog);
		BIO_printf(bio_err, "where options are\n");
		printhelp(ec_help);
		goto end;
		}

#ifndef OPENSSL_NO_ENGINE
        setup_engine(bio_err, engine, 0);
#endif

	if(!app_passwd(bio_err, passargin, passargout, &passin, &passout)) 
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
	else if (informat == FORMAT_PEM) 
		{
		if (pubin) 
			eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, 
				NULL);
		else 
			eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL,
				passin);
		} 
	else
		{
		BIO_printf(bio_err, "bad input format specified for key\n");
		goto end;
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
