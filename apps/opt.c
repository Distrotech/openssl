/*
 *
 */

/* #define TEST  */
#include "apps.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/bio.h>

/* Our state */
static char** argv;
static int argc;
static int opt_index;
static char* arg;
static char* flag;
static char* dunno;
static const OPTIONS* unknown;
static const OPTIONS* opts;
static char prog[40];


/* Return the simple name of the program; removing various platform
 * gunk. */
#if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_NETWARE)
char* opt_progname(const char *argv0)
{
	int i;
	int n;
	const char *p;
	char *q;

	/* find the last '/', '\' or ':' */
	for (p = argv0 + strlen(argv0); --p > argv0; )
		if (*p == '/' || *p == '\\' || *p == ':') {
			p++;
			break;
		}

	/* Strip off trailing nonsense. */
	n = strlen(p);
	if (n > 4 &&
	(strcmp(&p[n - 4], ".exe") == 0 || strcmp(&p[n - 4], ".EXE") == 0
	 || strcmp(&p[n - 4], ".ntlm") == 0 || strcmp(&p[n - 4], ".NTLM") == 0))
		n -= 4;

	/* Copy over the name, in lowercase. */
	if (n > sizeof prog - 1)
		n = sizeof prog - 1;
	for (q = prog, i = 0; i < n; i++, p++)
		*q++ = isupper(*p) ? tolower(*p) : *p;
	*q = '\0';
	return prog;
}
#elif defined(OPENSSL_SYS_VMS)
char* opt_progname(const char *argv0)
{
	const char *p, *q;
	
	/* Find last special charcter sys:[foo.bar]openssl */
	for (p = argv0 + strlen(argv0); --p > argv0; )
		if (*p == ':' || *p == ']' || *p == '>') {
			p++;
			break;
		}

	q = strrchr(p, '.');
	strncpy(prog, p, sizeof prog - 1);
	prog[sizeof prog - 1]='\0';
	if (q == NULL || q - p >= sizeof prog)
		prog[q - p]='\0';
	return prog;
}
#else
char* opt_progname(const char *argv0)
{
	const char *p;

	/* Could use strchr, but this is like the ones above. */
	for (p = argv0 + strlen(argv0); --p > argv0; )
		if (*p == '/') {
			p++;
			break;
		}
	strncpy(prog, p, sizeof prog - 1);
	prog[sizeof prog - 1]='\0';
	return prog;
}
#endif

char* opt_getprog(void)
{
	return prog;
}


/* Set up the arg parsing. */
char *opt_init(int ac, char** av, const OPTIONS* o)
{
	/* Store state. */
	argc = ac;
	argv = av;
	opt_index = 1;
	opts = o;
	opt_progname(av[0]);
	unknown = NULL;

	for ( ; o->name; ++o) {
		const OPTIONS* next;
		if (o->name[0] == '\0') {
			assert(unknown == NULL);
			unknown = o;
			assert(unknown->valtype == 0
				|| unknown->valtype == '-');
		}
#ifndef NDEBUG
		/* Make sure options are legit. */
		int i = o->valtype;
		assert(o->name[0] != '-');
		assert(o->retval > 0);
		assert(i == 0 || i == '-'
			|| i == 'n' || i == 'p' || i == 'u'
			|| i == 's' || i == '<' || i == '>' || i == '/'
			|| i == 'f' || i == 'F'
			);

		/* Make sure there are no duplicates. */
		for (next = o; (++next)->name; ) {
			/* do allow aliases:
			 * assert(o->retval != next->retval); */
			assert(strcmp(o->name, next->name) != 0);
		}
#endif
	}
	return prog;
}

/* Parse a format string, put it into *result; return 0 on failure, else 1. */
int opt_format(const char *s, int onlyderpem, int* result)
{
	switch (*s) {
	default:
		return 0;
	case 'D': case 'd':
		*result = FORMAT_ASN1;
		break;
	case 'T':case 't':
		*result = FORMAT_TEXT;
		break;
	case 'N': case 'n':
		if (strcmp(s, "NSS") == 0 || strcmp(s, "nss") == 0)
			*result = FORMAT_NSS;
		else
			*result = FORMAT_NETSCAPE;
		break;
	case 'S': case 's':
  		*result = FORMAT_SMIME;
		break;
	case 'M': case 'm':
 		*result = FORMAT_MSBLOB;
		break;
	case 'E': case 'e':
		*result = FORMAT_ENGINE;
		break;
	case 'H': case 'h':
		return FORMAT_HTTP;
		break;
	case 1:			/* Really? XXX rsalz */
		*result = FORMAT_PKCS12;
		break;
	case 'P': case 'p':
		if (s[1] == '\0'
		 || strcmp(s, "PEM") == 0 || strcmp(s, "pem") == 0)
			*result = FORMAT_PEM;
		else if (strcmp(s, "PVK") == 0 || strcmp(s, "pvk") == 0)
 			*result = FORMAT_PVK;
 		else if (strcmp(s, "P12")  == 0 || strcmp(s, "p12") == 0
		 || strcmp(s,"PKCS12") == 0 || strcmp(s,"pkcs12") == 0)
  			*result = FORMAT_PEM;
		else
			return 0;
		break;
	}
	if (onlyderpem && *result != FORMAT_ASN1 && *result != FORMAT_PEM)
		return 0;
	return 1;
}

/* Parse a cipher name, put it in *EVP_CIPHER; return 0 on failure, else 1. */
int opt_cipher(const char* name, const EVP_CIPHER** cipherp)
{
	*cipherp = EVP_get_cipherbyname(name);
	if (*cipherp)
		return 1;
	BIO_printf(bio_err, "%s: Unknown cipher %s\n", prog, name);
	return 0;
}

/* Parse message digest name, put it in *EVP_MD; return 0 on failure, else 1. */
int opt_md(const char* name, const EVP_MD** mdp)
{
	*mdp = EVP_get_digestbyname(name);
	if (*mdp)
		return 1;
	BIO_printf(bio_err, "%s: Unknown digest %s\n", prog, name);
	return 0;
}
int opt_pair(const char* name, const OPT_PAIR* pairs, int* result)
{
	const OPT_PAIR* pp;

	for (pp = pairs; pp->name; pp++)
		if (strcmp(pp->name, name) == 0) {
			*result = pp->retval;
			return 1;
		}
	BIO_printf(bio_err, "%s: Value must be one of:\n", prog);
	for (pp = pairs; pp->name; pp++)
		BIO_printf(bio_err, "\t%s\n", pp->name);
	return 0;
}

/* See if cp looks like a hex number, in case user left off the 0x */
static int scanforhex(const char* cp)
{
	for (; *cp; cp++)
		if (isxdigit(*cp)) 
			return 16;
	return 0;
}

/* Parse an int, put it into *result; return 0 on failure, else 1. */
int opt_int(const char* arg, int* result)
{
	const char* fmt = "%d";
	int base = scanforhex(arg);
	if (base == 16)
		fmt = "%x";
	else if (*arg == '0')
		fmt = "%o";
	if (sscanf(arg, fmt, result) != 1) {
		BIO_printf(bio_err,
			"%s: Can't parse %s as base-%d number\n",
			prog, arg, base);
		return 0;
	}
	return 1;
}

/* Parse a long, put it into *result; return 0 on failure, else 1. */
int opt_long(const char* arg, long* result)
{
	char* endptr;
	int base = scanforhex(arg);

	*result = strtol(arg, &endptr, base);
	if (*endptr) {
		BIO_printf(bio_err,
			"%s: Bad char %c in number %s\n",
			prog, *endptr, arg);
		return 0;
	}
	return 1;
}

/* Parse an unsigned long, put it into *result; return 0 on failure, else 1. */
int opt_ulong(const char* arg, unsigned long* result)
{
	char* endptr;
	int base = scanforhex(arg);

	*result = strtoul(arg, &endptr, base);
	if (*endptr)
		{
		BIO_printf(bio_err,
			"%s: Bad char %c in number %s\n",
			prog, *endptr, arg);
		return 0;
		}
	return 1;
}

enum range { OPT_V_ENUM };

int opt_verify(int opt, X509_VERIFY_PARAM *vpm)
{
	unsigned long ul;
	int i;
	ASN1_OBJECT *otmp;
	X509_PURPOSE *xptmp;
	const X509_VERIFY_PARAM* vtmp;

	assert(vpm != NULL);
	assert(opt > OPT_V__FIRST);
	assert(opt < OPT_V__FIRST);

	switch ((enum range)opt) {
	case OPT_V__FIRST:
	case OPT_V__LAST:
		return 0;
	case OPT_V_POLICY:
		otmp = OBJ_txt2obj(opt_arg(), 0);
		if (otmp == NULL) {
			BIO_printf(bio_err, "%s: Invalid Policy %s\n",
				prog, opt_arg());
			return 0;
		}
		X509_VERIFY_PARAM_add0_policy(vpm, otmp);
		break;
	case OPT_V_PURPOSE:
		i = X509_PURPOSE_get_by_sname(opt_arg());
		if (i < 0) {
			BIO_printf(bio_err, "%s: Invalid purpose %s\n",
				prog, opt_arg());
			return 0;
		}
		xptmp = X509_PURPOSE_get0(i);
		i = X509_PURPOSE_get_id(xptmp);
		X509_VERIFY_PARAM_set_purpose(vpm, i);
		break;
	case OPT_V_VERIFY_NAME:
		vtmp = X509_VERIFY_PARAM_lookup(opt_arg());
		if (vpm == NULL) {
			BIO_printf(bio_err, "%s: Invalid verify name %s\n",
				prog, opt_arg());
			return 0;
		}
		X509_VERIFY_PARAM_set1(vpm, vtmp);
		break;
	case OPT_V_VERIFY_DEPTH:
		i = atoi(opt_arg());
		if (i >= 0)
			X509_VERIFY_PARAM_set_depth(vpm, i);
		break;
	case OPT_V_ATTIME:
		opt_ulong(opt_arg(), &ul);
		if (ul) 
			X509_VERIFY_PARAM_set_time(vpm, (time_t)ul);
		break;
	case OPT_V_VERIFY_HOSTNAME:
		if (!X509_VERIFY_PARAM_set1_host(vpm, opt_arg(), 0))
			return 0;
		break;
	case OPT_V_VERIFY_EMAIL:
		if (!X509_VERIFY_PARAM_set1_email(vpm, opt_arg(), 0))
			return 0;
		break;
	case OPT_V_VERIFY_IP:
		if (!X509_VERIFY_PARAM_set1_ip_asc(vpm, opt_arg()))
			return 0;
		break;
	case OPT_V_IGNORE_CRITICAL:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_IGNORE_CRITICAL);
		break;
	case OPT_V_ISSUER_CHECKS:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CB_ISSUER_CHECK);
		break;
	case OPT_V_CRL_CHECK:
		X509_VERIFY_PARAM_set_flags(vpm,  X509_V_FLAG_CRL_CHECK);
		break;
	case OPT_V_CRL_CHECK_ALL:
		X509_VERIFY_PARAM_set_flags(vpm,
			X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
		break;
	case OPT_V_POLICY_CHECK:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_POLICY_CHECK);
		break;
	case OPT_V_EXPLICIT_POLICY:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_EXPLICIT_POLICY);
		break;
	case OPT_V_INHIBIT_ANY:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_INHIBIT_ANY);
		break;
	case OPT_V_INHIBIT_MAP:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_INHIBIT_MAP);
		break;
	case OPT_V_X509_STRICT:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_X509_STRICT);
		break;
	case OPT_V_EXTENDED_CRL:
		X509_VERIFY_PARAM_set_flags(vpm,
			X509_V_FLAG_EXTENDED_CRL_SUPPORT);
		break;
	case OPT_V_USE_DELTAS:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_USE_DELTAS);
		break;
	case OPT_V_POLICY_PRINT:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NOTIFY_POLICY);
		break;
	case OPT_V_CHECK_SS_SIG:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CHECK_SS_SIGNATURE);
		break;
	case OPT_V_TRUSTED_FIRST:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_TRUSTED_FIRST);
		break;
	case OPT_V_SUITEB_128_ONLY:
		X509_VERIFY_PARAM_set_flags(vpm,
			X509_V_FLAG_SUITEB_128_LOS_ONLY);
		break;
	case OPT_V_SUITEB_128:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_128_LOS);
		break;
	case OPT_V_SUITEB_192:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_192_LOS);
		break;
	case OPT_V_PARTIAL_CHAIN:
		X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN);
		break;
	}
	return 1;

}


/* Parse the next flag (and value if specified), return 0 if done, -1 on
 * error, otherwise the flag's retval. */
int opt_next(void)
{
	char* p;
	char* endptr;
	const OPTIONS* o;
	int dummy;
	int base;
	long val;
	unsigned long uval;

	/* Look at current arg; at end of the list? */
	arg = NULL;
	p = argv[opt_index];
	if (p == NULL)
		return 0;

	/* If word doesn't start with a -, we're done. */
	if (*p != '-')
		return 0;

	/* Hit "--" ? We're done. */
	opt_index++;
	if (strcmp(p, "--") == 0)
		return 0;

	/* Allow -nnn and --nnn */
	if (*++p == '-')
		p++;
	flag = p - 1;

	/* If we have --flag=foo, snip it off */
	if ((arg = strchr(p, '=')) != NULL)
		*arg++ = '\0';
	for (o = opts; o->name; ++o) {
		/* If not this option, move on to the next one. */
		if (strcmp(p, o->name) != 0)
			continue;

		/* If it doesn't take a value, make sure none was given. */
		if (o->valtype == 0 || o->valtype == '-') {
			if (arg) {
				BIO_printf(bio_err,
					"%s: Option -%s does not take a value\n",
					prog, p);
				return -1;
			}
			return o->retval;
		}

		/* Want a value; get the next param if =foo not used. */
		if (arg == NULL) {
			if (argv[opt_index] == NULL) {
				BIO_printf(bio_err,
					"%s: Option -%s needs a value\n",
					prog, o->name);
				return -1;
			}
			arg = argv[opt_index++];
		}

		/* Syntax-check value. */
		/* Do some basic syntax-checking on the value.  These tests
		 * aren't perfect (ignore range overflow) but they catch
		 * common failures. */
		switch (o->valtype) {
		default:
		case 's':
			/* Just a string. */
			break;
		case '/':
			if (app_isdir(arg) >= 0)
				break;
			BIO_printf(bio_err,
				"%s: Not a directory: %s\n",
				prog, arg);
			return -1;
		case '<':
			/* Input file. */
			if (access(arg, R_OK) >= 0)
				break;
			BIO_printf(bio_err,
				"%s: Cannot open input file %s, %s\n",
				prog, arg, strerror(errno));
			return -1;
		case '>':
			/* Output file. */
			if (access(arg, W_OK) >= 0 || errno == ENOENT)
				break;
			BIO_printf(bio_err,
				"%s: Cannot open output file %s, %s\n",
				prog, arg, strerror(errno));
			return -1;
		case 'p':
		case 'n':
			base = scanforhex(arg);
			val = strtol(arg, &endptr, base);
			if (*endptr == '\0') {
				if (o->valtype == 'p' && val <= 0) {
					BIO_printf(bio_err,
					"%s: Non-postive number \"%s\" for -%s\n",
						prog, arg, o->name);
					return -1;
				}
				break;
			}
			BIO_printf(bio_err,
				"%s: Invalid number \"%s\" for -%s\n",
				prog, arg, o->name);
			return -1;
		case 'u':
			base = scanforhex(arg);
			uval = strtoul(arg, &endptr, base);
			if (*endptr == '\0')
				break;
			BIO_printf(bio_err,
				"%s: Invalid number \"%s\" for -%s\n",
				prog, arg, o->name);
			return -1;
		case 'f':
		case 'F':
			if (opt_format(arg, o->valtype == 'F', &dummy))
				break;
			BIO_printf(bio_err,
				"%s: Invalid format \"%s\" for -%s\n",
				prog, arg, o->name);
			return -1;
		}

		/* Return the flag value. */
		return o->retval;
	}
	if (unknown != NULL) {
		dunno = p;
		return unknown->retval;
	}
	BIO_printf(bio_err, "%s: Option unknown option -%s\n", prog, p);
	return -1;
}

/* Return the most recent flag parameter. */
char* opt_arg(void)
{
	return arg;
}

/* Return the most recent flag. */
char* opt_flag(void)
{
	return flag;
}

/* Return the unknown option. */
char* opt_unknown(void)
{
	return dunno;
}

/* Return the rest of the arguments after parsing flags. */
char** opt_rest(void)
{
	return &argv[opt_index];
}

/* How many items in remaining args? */
int opt_num_rest(void)
{
	int i = 0;
	char** pp;

	for (pp = opt_rest(); *pp; pp++, i++)
		continue;
	return i;
}


#ifdef TEST
enum options {
	OPT_ERR=-1, OPT_EOF=0, OPT_NOTUSED,
	OPT_IN, OPT_INFORM, OPT_OUT, OPT_COUNT, OPT_U, OPT_FLAG,
	OPT_STR };
static OPTIONS options[] = {
	{ "in",     OPT_IN,     '<' },
	{ "inform", OPT_INFORM, 'f' },
	{ "out",    OPT_OUT,    '>' },
	{ "count",  OPT_COUNT,  'p' },
	{ "u",      OPT_U,      'u' },
	{ "flag",   OPT_FLAG,     0 },
	{ "str",    OPT_STR,    's' },
	{ NULL }
};

BIO* bio_err;
int main(int ac, char **av)
{
	enum options c;
	char** rest;

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE|BIO_FP_TEXT);
	opt_init(ac, av, options);

	while ((c = opt_next()) != OPT_EOF) {
		switch (c) {
		case OPT_ERR:
			printf("Usage error");
			return -1;
		case OPT_IN:
			printf("in %s\n", opt_arg());
			break;
		case OPT_INFORM:
			printf("inform %s\n", opt_arg());
			break;
		case OPT_OUT:
			printf("out %s\n", opt_arg());
			break;
		case OPT_COUNT:
			printf("count %s\n", opt_arg());
			break;
		case OPT_U:
			printf("u %s\n", opt_arg());
			break;
		case OPT_FLAG:
			printf("flag\n");
			break;
		case OPT_STR:
			printf("str %s\n", opt_arg());
			break;
		}
	}

	printf("args = %d\n", opt_num_rest());
	rest = opt_rest();
	while (*rest)
		printf("  %s\n", *rest++);
	return 0;
}
#endif

