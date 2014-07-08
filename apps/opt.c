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
			|| i == 's' || i == '<' || i == '>'
			|| i == 'f' || i == 'F'
			);

		/* Make sure there are no duplicates. */
		for (next = o; (++next)->name; ) {
			assert(o->retval != next->retval);
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

/* Parse the next flag (and value if specified), return 0 if done, -1 on
 * error, otherwise the flag's retval. */
int opt_next(void)
{
	char* p;
	char* endptr;
	const OPTIONS* o;
	int dummy;
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
			val = strtol(arg, &endptr, 0);
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
			uval = strtoul(arg, &endptr, 0);
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
	OPT_ERR=-1, OPT_EOF=0,
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
	int c;
	char** rest;

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE|BIO_FP_TEXT);
	opt_init(ac, av, options);

	while ((c = opt_next()) != 0) {
		if (c == -1)
			return 1;
		switch (c) {
		case 1:
			printf("in %s\n", opt_arg());
			break;
		case 2:
			printf("inform %s\n", opt_arg());
			break;
		case 3:
			printf("out %s\n", opt_arg());
			break;
		case 4:
			printf("out %s\n", opt_arg());
			break;
		case 5:
			printf("u %s\n", opt_arg());
			break;
		case 7:
			printf("flag\n");
			break;
		case 's':
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

