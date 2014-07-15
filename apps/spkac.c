/* apps/spkac.c */

/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999. Based on an original idea by Massimiliano Pala
 * (madwolf@openca.org).
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


enum options {
	OPT_ERR = -1, OPT_EOF = 0,
	OPT_NOOUT, OPT_PUBKEY, OPT_VERIFY, OPT_IN, OPT_OUT,
	OPT_ENGINE, OPT_KEY, OPT_CHALLENGE, OPT_PASSIN, OPT_SPKAC,
	OPT_SPKSECT,
};

OPTIONS spkac_options[] = {
	{ "in", OPT_IN, '<', "Input file" },
	{ "out", OPT_OUT, '>', "Output file" },
	{ "key", OPT_KEY, '<', "Create SPKAC using private key" },
	{ "passin", OPT_PASSIN, 's', "Input file pass phrase source" },
	{ "challenge", OPT_CHALLENGE, 's', "Challenge string" },
	{ "spkac", OPT_SPKAC, 's', "Alternative SPKAC name" },
	{ "noout", OPT_NOOUT, '-', "Don't print SPKAC" },
	{ "pubkey", OPT_PUBKEY, '-', "Output public key" },
	{ "verify", OPT_VERIFY, '-', "Verify SPKAC signature" },
	{ "spksect", OPT_SPKSECT, 's' },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device" },
#endif
	{ NULL }
};

int spkac_main(int argc, char **argv)
	{
	ENGINE *e = NULL;
	int i, ret = 1;
	BIO *in = NULL,*out = NULL;
	int verify=0,noout=0,pubkey=0;
	char *infile = NULL,*outfile = NULL,*prog;
	char *passinarg = NULL, *passin = NULL;
	const char *spkac = "SPKAC", *spksect = "default";
	char *spkstr = NULL;
	char *challenge = NULL, *keyfile = NULL;
	CONF *conf = NULL;
	NETSCAPE_SPKI *spki = NULL;
	EVP_PKEY *pkey = NULL;
	char *engine=NULL;
	enum options o;

	prog = opt_init(argc, argv, spkac_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
			opt_help(spkac_options);
			goto end;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_NOOUT:
			noout=1;
			break;
		case OPT_PUBKEY:
			pubkey=1;
			break;
		case OPT_VERIFY:
			verify=1;
			break;
		case OPT_PASSIN:
			passinarg= opt_arg();
			break;
		case OPT_KEY:
			keyfile= opt_arg();
			break;
		case OPT_CHALLENGE:
			challenge= opt_arg();
			break;
		case OPT_SPKAC:
			spkac= opt_arg();
			break;
		case OPT_SPKSECT:
			spksect= opt_arg();
			break;
		case OPT_ENGINE:
			engine= opt_arg();
			break;

		}
	}

	if(!app_passwd(bio_err, passinarg, NULL, &passin, NULL)) {
		BIO_printf(bio_err, "Error getting password\n");
		goto end;
	}

#ifndef OPENSSL_NO_ENGINE
        e = setup_engine(bio_err, engine, 0);
#endif

	if(keyfile) {
		pkey = load_key(bio_err,
				strcmp(keyfile, "-") ? keyfile : NULL,
				FORMAT_PEM, 1, passin, e, "private key");
		if(!pkey) {
			goto end;
		}
		spki = NETSCAPE_SPKI_new();
		if(challenge) ASN1_STRING_set(spki->spkac->challenge,
						 challenge, (int)strlen(challenge));
		NETSCAPE_SPKI_set_pubkey(spki, pkey);
		NETSCAPE_SPKI_sign(spki, pkey, EVP_md5());
		spkstr = NETSCAPE_SPKI_b64_encode(spki);

		out = bio_open_default(outfile, "w");
		if(out == NULL)
			goto end;
		BIO_printf(out, "SPKAC=%s\n", spkstr);
		OPENSSL_free(spkstr);
		ret = 0;
		goto end;
	}

	

	in = bio_open_default(infile, "r");
	if(in==NULL)
		goto end;

	conf = NCONF_new(NULL);
	i = NCONF_load_bio(conf, in, NULL);

	if(!i) {
		BIO_printf(bio_err, "Error parsing config file\n");
		ERR_print_errors(bio_err);
		goto end;
	}

	spkstr = NCONF_get_string(conf, spksect, spkac);
		
	if(!spkstr) {
		BIO_printf(bio_err, "Can't find SPKAC called \"%s\"\n", spkac);
		ERR_print_errors(bio_err);
		goto end;
	}

	spki = NETSCAPE_SPKI_b64_decode(spkstr, -1);
	
	if(!spki) {
		BIO_printf(bio_err, "Error loading SPKAC\n");
		ERR_print_errors(bio_err);
		goto end;
	}

	out = bio_open_default(outfile, "w");
	if(out == NULL)
		goto end;

	if(!noout) NETSCAPE_SPKI_print(out, spki);
	pkey = NETSCAPE_SPKI_get_pubkey(spki);
	if(verify) {
		i = NETSCAPE_SPKI_verify(spki, pkey);
		if (i > 0) BIO_printf(bio_err, "Signature OK\n");
		else {
			BIO_printf(bio_err, "Signature Failure\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if(pubkey) PEM_write_bio_PUBKEY(out, pkey);

	ret = 0;

end:
	NCONF_free(conf);
	NETSCAPE_SPKI_free(spki);
	BIO_free(in);
	BIO_free_all(out);
	EVP_PKEY_free(pkey);
	if(passin) OPENSSL_free(passin);
	return(ret);
	}
