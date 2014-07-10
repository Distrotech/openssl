/* apps/dsa.c */
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>


const char* dsa_help[] = {
	"-inform arg     input format - DER or PEM",
	"-outform arg    output format - DER or PEM",
	"-in arg         input file",
	"-passin arg     input file pass phrase source",
	"-out arg        output file",
	"-passout arg    output file pass phrase source",
#ifndef OPENSSL_NO_ENGINE
	"-engine e       use engine e, possibly a hardware device.",
#endif
	"-des            encrypt PEM output with cbc des",
	"-des3           encrypt PEM output with ede cbc des using 168 bit key",
#ifndef OPENSSL_NO_IDEA
	"-idea           encrypt PEM output with cbc idea",
#endif
#ifndef OPENSSL_NO_AES
	"-aes128, -aes192, -aes256",
	"                 encrypt PEM output with cbc aes",
#endif
#ifndef OPENSSL_NO_CAMELLIA
	"-camellia128, -camellia192, -camellia256",
	"                 encrypt PEM output with cbc camellia",
#endif
#ifndef OPENSSL_NO_SEED
	"-seed           encrypt PEM output with cbc seed",
#endif
	"-text           print the key in text",
	"-noout          don't print key out",
	"-modulus        print the DSA public value",
	NULL
};

enum options {
	OPT_ERR = -1, OPT_EOF = 0,
	OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT,
	OPT_ENGINE, OPT_PVK_STRONG, OPT_PVK_WEAK,
	OPT_PVK_NONE, OPT_NOOUT, OPT_TEXT, OPT_MODULUS, OPT_PUBIN,
	OPT_PUBOUT, OPT_CIPHER, OPT_PASSIN, OPT_PASSOUT,
};
static OPTIONS options[] = {
	{ "inform", OPT_INFORM, 'F' },
	{ "outform", OPT_OUTFORM, 'F' },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's' },
#endif
	{ "in", OPT_IN, '<' },
	{ "out", OPT_OUT, '>' },
	{ "pvk-strong", OPT_PVK_STRONG, '-' },
	{ "pvk-weak", OPT_PVK_WEAK, '-' },
	{ "pvk-none", OPT_PVK_NONE, '-' },
	{ "noout", OPT_NOOUT, '-' },
	{ "text", OPT_TEXT, '-' },
	{ "modulus", OPT_MODULUS, '-' },
	{ "pubin", OPT_PUBIN, '-' },
	{ "pubout", OPT_PUBOUT, '-' },
	{ "passin", OPT_PASSIN, 's' },
	{ "passout", OPT_PASSOUT, 's' },
	{ "", OPT_CIPHER, '-' },
	{ NULL }
};

int dsa_main(int argc, char **argv)
	{
	ENGINE *e = NULL;
	int ret=1;
	DSA *dsa=NULL;
	int i;
	const EVP_CIPHER *enc=NULL;
	BIO *in=NULL,*out=NULL;
	int informat=FORMAT_PEM,outformat=FORMAT_PEM,text=0,noout=0;
	int pubin = 0, pubout = 0;
	char *infile=NULL,*outfile=NULL,*prog;
	char *engine=NULL;
	char *passinarg = NULL, *passoutarg = NULL;
	char *passin = NULL, *passout = NULL;
	int modulus=0;
	int pvk_encr = 2;
	enum options o;

	prog = opt_init(argc, argv, options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
			BIO_printf(bio_err,"Valid options are:\n");
			printhelp(dsa_help);
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
		case OPT_ENGINE:
			engine = opt_arg();
			break;
		case OPT_PASSIN:
			passinarg = opt_arg();
			break;
		case OPT_PASSOUT:
			passoutarg= opt_arg();
			break;
		case OPT_PVK_STRONG:
			pvk_encr=2;
			break;
		case OPT_PVK_WEAK:
			pvk_encr=1;
			break;
		case OPT_PVK_NONE:
			pvk_encr=0;
			break;
		case OPT_NOOUT:
			noout=1;
			break;
		case OPT_TEXT:
			text=1;
			break;
		case OPT_MODULUS:
			modulus=1;
			break;
		case OPT_PUBIN:
			pubin=1;
			break;
		case OPT_PUBOUT:
			pubout=1;
			break;
		case OPT_CIPHER:
			if (!opt_cipher(opt_unknown(), &enc))
				goto end;
			break;
		}
	}


#ifndef OPENSSL_NO_ENGINE
        e = setup_engine(bio_err, engine, 0);
#endif

	if(!app_passwd(bio_err, passinarg, passoutarg, &passin, &passout)) {
		BIO_printf(bio_err, "Error getting passwords\n");
		goto end;
	}

	in = bio_open_default(infile, "r");
	if (in == NULL)
		goto end;

	BIO_printf(bio_err,"read DSA key\n");

	{
	EVP_PKEY	*pkey;

	if (pubin)
		pkey = load_pubkey(bio_err, infile, informat, 1,
			passin, e, "Public Key");
	else
		pkey = load_key(bio_err, infile, informat, 1,
			passin, e, "Private Key");

	if (pkey)
		{
		dsa = EVP_PKEY_get1_DSA(pkey);
		EVP_PKEY_free(pkey);
		}
	}
	if (dsa == NULL)
		{
		BIO_printf(bio_err,"unable to load Key\n");
		ERR_print_errors(bio_err);
		goto end;
		}

	out = bio_open_default(outfile, "w");
	if (out == NULL)
		goto end;

	if (text) 
		if (!DSA_print(out,dsa,0))
			{
			perror(outfile);
			ERR_print_errors(bio_err);
			goto end;
			}

	if (modulus)
		{
		BIO_printf(out,"Public Key=");
		BN_print(out,dsa->pub_key);
		BIO_printf(out,"\n");
		}

	if (noout) goto end;
	BIO_printf(bio_err,"writing DSA key\n");
	if 	(outformat == FORMAT_ASN1) {
		if(pubin || pubout) i=i2d_DSA_PUBKEY_bio(out,dsa);
		else i=i2d_DSAPrivateKey_bio(out,dsa);
	} else if (outformat == FORMAT_PEM) {
		if(pubin || pubout)
			i=PEM_write_bio_DSA_PUBKEY(out,dsa);
		else i=PEM_write_bio_DSAPrivateKey(out,dsa,enc,
							NULL,0,NULL, passout);
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_RC4)
	} else if (outformat == FORMAT_MSBLOB || outformat == FORMAT_PVK) {
		EVP_PKEY *pk;
		pk = EVP_PKEY_new();
		EVP_PKEY_set1_DSA(pk, dsa);
		if (outformat == FORMAT_PVK)
			i = i2b_PVK_bio(out, pk, pvk_encr, 0, passout);
		else if (pubin || pubout)
			i = i2b_PublicKey_bio(out, pk);
		else
			i = i2b_PrivateKey_bio(out, pk);
		EVP_PKEY_free(pk);
#endif
	} else {
		BIO_printf(bio_err,"bad output format specified for outfile\n");
		goto end;
		}
	if (i <= 0)
		{
		BIO_printf(bio_err,"unable to write private key\n");
		ERR_print_errors(bio_err);
		goto end;
		}
	ret=0;
end:
	if(in != NULL) BIO_free(in);
	if(out != NULL) BIO_free_all(out);
	if(dsa != NULL) DSA_free(dsa);
	if(passin) OPENSSL_free(passin);
	if(passout) OPENSSL_free(passout);
	return(ret);
	}
#else /* !OPENSSL_NO_DSA */

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
