/* apps/s_time.c */
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

#define NO_SHUTDOWN

/*-----------------------------------------
   s_time - SSL client connection timer program
   Written and donated by Larry Streepy <streepy@healthcare.com>
  -----------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_SOCKETS
#include "apps.h"
#ifdef OPENSSL_NO_STDIO
#define APPS_WIN16
#endif
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include "s_apps.h"
#include <openssl/err.h>
#ifdef WIN32_STUFF
#include "winmain.h"
#include "wintext.h"
#endif
#if !defined(OPENSSL_SYS_MSDOS)
#include OPENSSL_UNISTD
#endif


#undef ioctl
#define ioctl ioctlsocket

#define SSL_CONNECT_NAME	"localhost:4433"

/*#define TEST_CERT "client.pem" */ /* no default cert. */

#undef BUFSIZZ
#define BUFSIZZ 1024*10

#define MYBUFSIZ 1024*8

#undef min
#undef max
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

#undef SECONDS
#define SECONDS	30
#define SECONDSSTR "30"

extern int verify_depth;
extern int verify_error;

static SSL *doConnection(SSL *scon, const char* host, SSL_CTX* ctx);

const char* s_time_help[] = {
	"-time arg      max number of seconds to collect data, default" SECONDSSTR,
	"-verify arg    turn on peer certificate verification, arg == depth",
	"-cert arg      certificate file to use, PEM format assumed",
	"-key arg       RSA file to use, PEM format assumed, key is in cert file",
	"               file if not specified by this option",
	"-CApath arg    PEM format directory of CA's",
	"-CAfile arg    PEM format file of CA's",
	"-cipher        preferred cipher to use, play with 'openssl ciphers'",

	"-connect host:port  where to connect to (default is "SSL_CONNECT_NAME ")",
#ifndef OPENSSL_NO_SSL2
	"-ssl2          just use SSLv2",
#endif
#ifndef OPENSSL_NO_SSL3
	"-ssl3          just use SSLv3",
#endif
	"-bugs          turn on SSL bug compatibility",
	"-new           just time new connections",
	"-reuse         just time connection reuse",
	"-www page      retrieve 'page' from the site",
#ifdef FIONBIO
	"-nbio          use non-blocking IO",
#endif
	NULL
};

enum options {
	OPT_ERR = -1, OPT_EOF = 0, OPT_CONNECT, OPT_CIPHER, OPT_CERT,
	OPT_KEY, OPT_CAPATH, OPT_CAFILE, OPT_NEW, OPT_REUSE, OPT_BUGS,
	OPT_VERIFY, OPT_TIME, OPT_WWW,
#ifndef OPENSSL_NO_SSL2
	OPT_SSL2,
#endif
#ifndef OPENSSL_NO_SSL3
	OPT_SSL3,
#endif
#ifdef FIONBIO
	OPT_NBIO,
#endif
};

static OPTIONS options[] = {
	{ "connect", OPT_CONNECT, 's' },
	{ "cipher", OPT_CIPHER, 's' },
	{ "cert", OPT_CERT, '<' },
	{ "key", OPT_KEY, '<' },
	{ "CApath", OPT_CAPATH, '/' },
	{ "cafile", OPT_CAFILE, '<' },
	{ "new", OPT_NEW, '-' },
	{ "reuse", OPT_REUSE, '-' },
	{ "bugs", OPT_BUGS, '-' },
	{ "verify", OPT_VERIFY, 'p' },
	{ "time", OPT_TIME, 'p' },
	{ "www", OPT_WWW, 's' },
#ifndef OPENSSL_NO_SSL2
	{ "ssl2", OPT_SSL2, '-' },
#endif
#ifndef OPENSSL_NO_SSL3
	{ "ssl3", OPT_SSL3, '-' },
#endif
#ifdef FIONBIO
	{ "nbio", OPT_NBIO, '-' },
#endif
	{ NULL }
};


#define START	0
#define STOP	1

static double tm_Time_F(int s)
	{
	return app_tminterval(s,1);
	}

int s_time_main(int argc, char **argv)
	{
	double totalTime=0.0;
	int nConn=0;
	SSL *scon=NULL;
	long finishtime=0;
	int ret=1,i;
	MS_STATIC char buf[1024*8];
	int ver;
	char* prog;
	char *host=SSL_CONNECT_NAME, *certfile =NULL, *keyfile=NULL;
	char *CApath=NULL, *CAfile=NULL, *cipher=NULL;
	int maxtime=SECONDS;
	const SSL_METHOD *meth=NULL;
	SSL_CTX *ctx=NULL;
	char *www_path=NULL;
	long bytes_read=0; 
	int st_bugs=0;
	int perform=3;
	enum options o;
#ifdef FIONBIO
	int t_nbio=0;
#endif
#ifdef OPENSSL_SYS_WIN32
	int exitNow=0;		/* Set when it's time to exit main */
#endif


#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
	meth=SSLv23_client_method();
#elif !defined(OPENSSL_NO_SSL3)
	meth=SSLv3_client_method();
#elif !defined(OPENSSL_NO_SSL2)
	meth=SSLv2_client_method();
#endif

	verify_depth=0;
	verify_error=X509_V_OK;

	prog = opt_init(argc, argv, options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
err:
			BIO_printf(bio_err,"Valid options are:\n");
			printhelp(s_time_help);
			goto end;
		case OPT_CONNECT:
			host= opt_arg();
			break;
		case OPT_REUSE:
			perform=2;
			break;
		case OPT_NEW:
			perform=1;
			break;
		case OPT_VERIFY:
			if (!opt_int(opt_arg(), &verify_depth))
				goto err;
			BIO_printf(bio_err, "%s verify depth is %d\n",
				prog, verify_depth);
			break;
		case OPT_CERT:
			certfile = opt_arg();
			break;
		case OPT_KEY:
			keyfile= opt_arg();
			break;
		case OPT_CAPATH:
			CApath= opt_arg();
			break;
		case OPT_CAFILE:
			CAfile= opt_arg();
			break;
		case OPT_CIPHER:
			cipher= opt_arg();
			break;
		case OPT_BUGS:
			st_bugs=1;
			break;
		case OPT_TIME:
			if (!opt_int(opt_arg(), &maxtime))
				goto err;
			break;
		case OPT_WWW:
			www_path = opt_arg();
			if(strlen(www_path) > MYBUFSIZ-100) {
				BIO_printf(bio_err,
					"%s: -www option too long\n", prog);
				goto end;
			}
			break;
#ifndef OPENSSL_NO_SSL2
		case OPT_SSL2:
			meth=SSLv2_client_method();
			break;
#endif
#ifndef OPENSSL_NO_SSL3
		case OPT_SSL3:
			meth=SSLv3_client_method();
			break;
#endif
#ifdef FIONBIO
		case OPT_NBIO:
			t_nbio = 1;
			break;
#endif
		}
	}

	OpenSSL_add_ssl_algorithms();
	if ((ctx=SSL_CTX_new(meth)) == NULL) return(1);

	SSL_CTX_set_quiet_shutdown(ctx,1);

	if (st_bugs) SSL_CTX_set_options(ctx,SSL_OP_ALL);
	SSL_CTX_set_cipher_list(ctx,cipher);
	if(!set_cert_stuff(ctx,certfile ,keyfile)) 
		goto end;

	if ((!SSL_CTX_load_verify_locations(ctx,CAfile,CApath)) ||
		(!SSL_CTX_set_default_verify_paths(ctx)))
		{
		/* BIO_printf(bio_err,"error setting default verify locations\n"); */
		ERR_print_errors(bio_err);
		/* goto end; */
		}

	if (cipher == NULL)
		cipher = getenv("SSL_CIPHER");

	if (cipher == NULL ) {
		fprintf( stderr, "No CIPHER specified\n" );
		goto end;
	}

	if (!(perform & 1)) goto next;
	printf( "Collecting connection statistics for %d seconds\n", maxtime );

	/* Loop and time how long it takes to make connections */

	bytes_read=0;
	finishtime=(long)time(NULL)+maxtime;
	tm_Time_F(START);
	for (;;)
		{
		if (finishtime < (long)time(NULL)) break;
#ifdef WIN32_STUFF

		if( flushWinMsgs(0) == -1 )
			goto end;

		if( waitingToDie || exitNow )		/* we're dead */
			goto end;
#endif

		if( (scon = doConnection( NULL,host,ctx )) == NULL )
			goto end;

		if (www_path != NULL)
			{
			BIO_snprintf(buf,sizeof buf,"GET %s HTTP/1.0\r\n\r\n",www_path);
			SSL_write(scon,buf,strlen(buf));
			while ((i=SSL_read(scon,buf,sizeof(buf))) > 0)
				bytes_read+=i;
			}

#ifdef NO_SHUTDOWN
		SSL_set_shutdown(scon,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
		SSL_shutdown(scon);
#endif
		SHUTDOWN2(SSL_get_fd(scon));

		nConn += 1;
		if (SSL_session_reused(scon))
			ver='r';
		else
			{
			ver=SSL_version(scon);
			if (ver == TLS1_VERSION)
				ver='t';
			else if (ver == SSL3_VERSION)
				ver='3';
			else if (ver == SSL2_VERSION)
				ver='2';
			else
				ver='*';
			}
		fputc(ver,stdout);
		fflush(stdout);

		SSL_free( scon );
		scon=NULL;
		}
	totalTime += tm_Time_F(STOP); /* Add the time for this iteration */

	i=(int)((long)time(NULL)-finishtime+maxtime);
	printf( "\n\n%d connections in %.2fs; %.2f connections/user sec, bytes read %ld\n", nConn, totalTime, ((double)nConn/totalTime),bytes_read);
	printf( "%d connections in %ld real seconds, %ld bytes read per connection\n",nConn,(long)time(NULL)-finishtime+maxtime,bytes_read/nConn);

	/* Now loop and time connections using the same session id over and over */

next:
	if (!(perform & 2)) goto end;
	printf( "\n\nNow timing with session id reuse.\n" );

	/* Get an SSL object so we can reuse the session id */
	if( (scon = doConnection( NULL,host,ctx )) == NULL )
		{
		fprintf( stderr, "Unable to get connection\n" );
		goto end;
		}

	if (www_path != NULL)
		{
		BIO_snprintf(buf,sizeof buf,"GET %s HTTP/1.0\r\n\r\n",www_path);
		SSL_write(scon,buf,strlen(buf));
		while (SSL_read(scon,buf,sizeof(buf)) > 0)
			;
		}
#ifdef NO_SHUTDOWN
	SSL_set_shutdown(scon,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
	SSL_shutdown(scon);
#endif
	SHUTDOWN2(SSL_get_fd(scon));

	nConn = 0;
	totalTime = 0.0;

	finishtime=(long)time(NULL)+maxtime;

	printf( "starting\n" );
	bytes_read=0;
	tm_Time_F(START);
		
	for (;;)
		{
		if (finishtime < (long)time(NULL)) break;

#ifdef WIN32_STUFF
		if( flushWinMsgs(0) == -1 )
			goto end;

		if( waitingToDie || exitNow )	/* we're dead */
			goto end;
#endif

	 	if( (doConnection( scon,host,ctx )) == NULL )
			goto end;

		if (www_path)
			{
			BIO_snprintf(buf,sizeof buf,"GET %s HTTP/1.0\r\n\r\n",www_path);
			SSL_write(scon,buf,strlen(buf));
			while ((i=SSL_read(scon,buf,sizeof(buf))) > 0)
				bytes_read+=i;
			}

#ifdef NO_SHUTDOWN
		SSL_set_shutdown(scon,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
		SSL_shutdown(scon);
#endif
		SHUTDOWN2(SSL_get_fd(scon));
	
		nConn += 1;
		if (SSL_session_reused(scon))
			ver='r';
		else
			{
			ver=SSL_version(scon);
			if (ver == TLS1_VERSION)
				ver='t';
			else if (ver == SSL3_VERSION)
				ver='3';
			else if (ver == SSL2_VERSION)
				ver='2';
			else
				ver='*';
			}
		fputc(ver,stdout);
		fflush(stdout);
		}
	totalTime += tm_Time_F(STOP); /* Add the time for this iteration*/


	printf( "\n\n%d connections in %.2fs; %.2f connections/user sec, bytes read %ld\n", nConn, totalTime, ((double)nConn/totalTime),bytes_read);
	printf( "%d connections in %ld real seconds, %ld bytes read per connection\n",nConn,(long)time(NULL)-finishtime+maxtime,bytes_read/nConn);

	ret=0;
end:
	if (scon != NULL) SSL_free(scon);

	if (ctx != NULL)
		SSL_CTX_free(ctx);
	return(ret);
	}

/***********************************************************************
 * doConnection - make a connection
 */
static SSL *doConnection(SSL *scon, const char* host, SSL_CTX *ctx)
	{
	BIO *conn;
	SSL *serverCon;
	int width, i;
	fd_set readfds;

	if ((conn=BIO_new(BIO_s_connect())) == NULL)
		return(NULL);

	BIO_set_conn_hostname(conn,host);

	if (scon == NULL)
		serverCon=SSL_new(ctx);
	else
		{
		serverCon=scon;
		SSL_set_connect_state(serverCon);
		}

	SSL_set_bio(serverCon,conn,conn);

#if 0
	if( scon != NULL )
		SSL_set_session(serverCon,SSL_get_session(scon));
#endif

	/* ok, lets connect */
	for(;;) {
		i=SSL_connect(serverCon);
		if (BIO_sock_should_retry(i))
			{
			BIO_printf(bio_err,"DELAY\n");

			i=SSL_get_fd(serverCon);
			width=i+1;
			FD_ZERO(&readfds);
			openssl_fdset(i,&readfds);
			/* Note: under VMS with SOCKETSHR the 2nd parameter
			 * is currently of type (int *) whereas under other
			 * systems it is (void *) if you don't have a cast it
			 * will choke the compiler: if you do have a cast then
			 * you can either go for (int *) or (void *).
			 */
			select(width,(void *)&readfds,NULL,NULL,NULL);
			continue;
			}
		break;
		}
	if(i <= 0)
		{
		BIO_printf(bio_err,"ERROR\n");
		if (verify_error != X509_V_OK)
			BIO_printf(bio_err,"verify error:%s\n",
				X509_verify_cert_error_string(verify_error));
		else
			ERR_print_errors(bio_err);
		if (scon == NULL)
			SSL_free(serverCon);
		return NULL;
		}

	return serverCon;
	}


