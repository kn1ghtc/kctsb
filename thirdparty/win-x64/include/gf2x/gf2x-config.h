/* gf2x/gf2x-config.h.  Generated from gf2x-config.h.in by configure.  */
/* gf2x/gf2x-config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if using 'alloca.c'. */
/* #undef C_ALLOCA */

/* This is defined if gf2x was configured with --enable-fft-interface */
/* #undef GF2X_HAS_FFT_INTERFACE_SUPPORT */

/* Define if pclmul code as present in the source tree is supported by the
   compiler */
/* #undef GF2X_HAVE_PCLMUL_SUPPORT */

/* Define if sse-2 code as present in the source tree is supported by the
   compiler */
#define GF2X_HAVE_SSE2_SUPPORT 1

/* Define if sse-3 code as present in the source tree is supported by the
   compiler */
#define GF2X_HAVE_SSE3_SUPPORT 1

/* Define if sse-4.1 code as present in the source tree is supported by the
   compiler */
/* #undef GF2X_HAVE_SSE41_SUPPORT */

/* Define if ssse3 code as present in the source tree is supported by the
   compiler */
#define GF2X_HAVE_SSSE3_SUPPORT 1

/* This is defined if gf2x was compiled from an LGPL tarball */
/* #undef GF2X_IS_LGPL_VARIANT */

/* Have LGPL code (no GPL taint) */
#define GPL_CODE_PRESENT 1

/* Define to 1 if you have 'alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if <alloca.h> works. */
/* #undef HAVE_ALLOCA_H */

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define if __attribute__((visibility("hidden"))) is supported. */
/* #undef HAVE_HIDDEN_VISIBILITY_ATTRIBUTE */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if clock() returns non-constant values. */
/* #undef HAVE_NONCONSTANT_CLOCK */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "gf2x"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "gf2x"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "gf2x 1.3.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "gf2x"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.3.0"

/* The size of 'unsigned long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG 4

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if all of the C89 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "1.3.0"

/* Define as 'unsigned int' if <stddef.h> doesn't define. */
/* #undef size_t */
