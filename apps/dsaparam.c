/* apps/dsaparam.c */
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
/* Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code */
#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#ifndef OPENSSL_NO_DSA
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


#ifdef GENCB_TEST

static int stop_keygen_flag = 0;

static void timebomb_sigalarm(int foo)
	{
	stop_keygen_flag = 1;
	}

#endif

static int dsa_cb(int p, int n, BN_GENCB *cb);

const char* dsaparam_help[] = {
	"-inform arg   input format - DER or PEM",
	"-outform arg  output format - DER or PEM",
	"-in arg       input file",
	"-out arg      output file",
	"-text         print as text",
	"-C            Output C code",
	"-noout        no output",
	"-genkey       generate a DSA key",
	"-rand         files to use for random number input",
#ifndef OPENSSL_NO_ENGINE
	"-engine e     use engine e, possibly a hardware device.",
#endif
#ifdef GENCB_TEST
	"-timebomb n   interrupt keygen after <n> seconds",
#endif
	NULL
};

enum options {
	OPT_ERR = -1, OPT_EOF = 0,
	OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_TEXT, OPT_C,
	OPT_NOOUT, OPT_GENKEY, OPT_RAND, OPT_NON_FIPS_ALLOW, OPT_ENGINE,
	OPT_TIMEBOMB,
};

static OPTIONS options[] = {
	{ "inform", OPT_INFORM, 'F' },
	{ "outform", OPT_OUTFORM, 'F' },
	{ "in", OPT_IN, '<' },
	{ "out", OPT_OUT, '>' },
	{ "text", OPT_TEXT, '-' },
	{ "C", OPT_C, '-' },
	{ "noout", OPT_NOOUT, '-' },
	{ "genkey", OPT_GENKEY, '-' },
	{ "rand", OPT_RAND, 's' },
	{ "non-fips-allow", OPT_NON_FIPS_ALLOW, '-' },
#ifndef OPENSSL_NO_ENGINE
	{ "engine", OPT_ENGINE, 's' },
#endif
#ifdef GENCB_TEST
	{ "timebomb", OPT_TIMEBOMB, 'p' },
#endif
	{ NULL }
};

int dsaparam_main(int argc, char **argv)
	{
	DSA *dsa=NULL;
	BIO *in=NULL,*out=NULL;
	int i,text=0;
	int numbits=-1,num,genkey=0, need_rand=0, non_fips_allow=0;
	int informat=FORMAT_PEM,outformat=FORMAT_PEM,noout=0,C=0,ret=1;
	char *infile=NULL,*outfile=NULL,*prog,*inrand=NULL;
	char *engine=NULL;
	int timebomb=0;
	enum options o;

	prog = opt_init(argc, argv, options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
			BIO_printf(bio_err,"Valid options are:\n");
			printhelp(dsaparam_help);
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
		case OPT_TIMEBOMB:
			timebomb = atoi(opt_arg());
			break;
		case OPT_TEXT:
			text = 1;
			break;
		case OPT_C:
			C = 1;
			break;
		case OPT_GENKEY:
			genkey = need_rand = 1;
			break;
		case OPT_RAND:
			inrand = opt_arg();
			need_rand = 1;
			break;
		case OPT_NOOUT:
			noout = 1;
			break;
		case OPT_NON_FIPS_ALLOW:
			non_fips_allow = 1;
			break;
		}
	}

	argc = opt_num_rest();
	argv = opt_rest();
	if (argc == 1) {
		if ( !opt_int(argv[0], &num))
			goto end;
		/* generate a key */
		numbits = num;
		need_rand = 1;
	}

	in = bio_open_default(infile, "r");
	if (in == NULL)
		goto end;
	out = bio_open_default(outfile, "w");
	if (out == NULL)
		goto end;

#ifndef OPENSSL_NO_ENGINE
        setup_engine(bio_err, engine, 0);
#endif

	if (need_rand)
		{
		app_RAND_load_file(NULL, bio_err, (inrand != NULL));
		if (inrand != NULL)
			BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
				app_RAND_load_files(inrand));
		}

	if (numbits > 0)
		{
		BN_GENCB cb;
		BN_GENCB_set(&cb, dsa_cb, bio_err);
		assert(need_rand);
		dsa = DSA_new();
		if(!dsa)
			{
			BIO_printf(bio_err,"Error allocating DSA object\n");
			goto end;
			}
		if (non_fips_allow)
			dsa->flags |= DSA_FLAG_NON_FIPS_ALLOW;
		BIO_printf(bio_err,"Generating DSA parameters, %d bit long prime\n",num);
	        BIO_printf(bio_err,"This could take some time\n");
#ifdef GENCB_TEST
		if(timebomb > 0)
	{
		struct sigaction act;
		act.sa_handler = timebomb_sigalarm;
		act.sa_flags = 0;
		BIO_printf(bio_err,"(though I'll stop it if not done within %d secs)\n",
				timebomb);
		if(sigaction(SIGALRM, &act, NULL) != 0)
			{
			BIO_printf(bio_err,"Error, couldn't set SIGALRM handler\n");
			goto end;
			}
		alarm(timebomb);
	}
#endif
	        if(!DSA_generate_parameters_ex(dsa,num,NULL,0,NULL,NULL, &cb))
			{
#ifdef GENCB_TEST
			if(stop_keygen_flag)
				{
				BIO_printf(bio_err,"DSA key generation time-stopped\n");
				/* This is an asked-for behaviour! */
				ret = 0;
				goto end;
				}
#endif
			ERR_print_errors(bio_err);
			BIO_printf(bio_err,"Error, DSA key generation failed\n");
			goto end;
			}
		}
	else if	(informat == FORMAT_ASN1)
		dsa=d2i_DSAparams_bio(in,NULL);
	else
		dsa=PEM_read_bio_DSAparams(in,NULL,NULL,NULL);
	if (dsa == NULL)
		{
		BIO_printf(bio_err,"unable to load DSA parameters\n");
		ERR_print_errors(bio_err);
		goto end;
		}

	if (text)
		{
		DSAparams_print(out,dsa);
		}
	
	if (C)
		{
		unsigned char *data;
		int l,len,bits_p;

		len=BN_num_bytes(dsa->p);
		bits_p=BN_num_bits(dsa->p);
		data=(unsigned char *)OPENSSL_malloc(len+20);
		if (data == NULL)
			{
			perror("OPENSSL_malloc");
			goto end;
			}
		l=BN_bn2bin(dsa->p,data);
		printf("static unsigned char dsa%d_p[]={",bits_p);
		for (i=0; i<l; i++)
			{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
			}
		printf("\n\t};\n");

		l=BN_bn2bin(dsa->q,data);
		printf("static unsigned char dsa%d_q[]={",bits_p);
		for (i=0; i<l; i++)
			{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
			}
		printf("\n\t};\n");

		l=BN_bn2bin(dsa->g,data);
		printf("static unsigned char dsa%d_g[]={",bits_p);
		for (i=0; i<l; i++)
			{
			if ((i%12) == 0) printf("\n\t");
			printf("0x%02X,",data[i]);
			}
		printf("\n\t};\n\n");

		printf("DSA *get_dsa%d()\n\t{\n",bits_p);
		printf("\tDSA *dsa;\n\n");
		printf("\tif ((dsa=DSA_new()) == NULL) return(NULL);\n");
		printf("\tdsa->p=BN_bin2bn(dsa%d_p,sizeof(dsa%d_p),NULL);\n",
			bits_p,bits_p);
		printf("\tdsa->q=BN_bin2bn(dsa%d_q,sizeof(dsa%d_q),NULL);\n",
			bits_p,bits_p);
		printf("\tdsa->g=BN_bin2bn(dsa%d_g,sizeof(dsa%d_g),NULL);\n",
			bits_p,bits_p);
		printf("\tif ((dsa->p == NULL) || (dsa->q == NULL) || (dsa->g == NULL))\n");
		printf("\t\t{ DSA_free(dsa); return(NULL); }\n");
		printf("\treturn(dsa);\n\t}\n");
		}


	if (!noout)
		{
		if 	(outformat == FORMAT_ASN1)
			i=i2d_DSAparams_bio(out,dsa);
		else
			i=PEM_write_bio_DSAparams(out,dsa);
		if (!i)
			{
			BIO_printf(bio_err,"unable to write DSA parameters\n");
			ERR_print_errors(bio_err);
			goto end;
			}
		}
	if (genkey)
		{
		DSA *dsakey;

		assert(need_rand);
		if ((dsakey=DSAparams_dup(dsa)) == NULL) goto end;
		if (non_fips_allow)
			dsakey->flags |= DSA_FLAG_NON_FIPS_ALLOW;
		if (!DSA_generate_key(dsakey))
			{
			ERR_print_errors(bio_err);
			DSA_free(dsakey);
			goto end;
			}
		if 	(outformat == FORMAT_ASN1)
			i=i2d_DSAPrivateKey_bio(out,dsakey);
		else
			i=PEM_write_bio_DSAPrivateKey(out,dsakey,NULL,NULL,0,NULL,NULL);
		DSA_free(dsakey);
		}
	if (need_rand)
		app_RAND_write_file(NULL, bio_err);
	ret=0;
end:
	if (in != NULL) BIO_free(in);
	if (out != NULL) BIO_free_all(out);
	if (dsa != NULL) DSA_free(dsa);
	return(ret);
	}

static int dsa_cb(int p, int n, BN_GENCB *cb)
	{
	char c='*';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	BIO_write(cb->arg,&c,1);
	(void)BIO_flush(cb->arg);
#ifdef LINT
	p=n;
#endif
#ifdef GENCB_TEST
	if(stop_keygen_flag)
		return 0;
#endif
	return 1;
	}
#else /* !OPENSSL_NO_DSA */

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
