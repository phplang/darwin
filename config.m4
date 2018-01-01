dnl $Id$
dnl config.m4 for extension darwin

PHP_ARG_ENABLE(darwin, whether to enable darwin support,
[  --disable-darwin         Disable darwin support], yes)

if test "$PHP_DARWIN" != "no"; then
  dnl Requires 10.12.4
  AC_TRY_COMPILE([
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
  ],[
int main(void) {
  SecCertificateCopyNormalizedIssuerSequence(NULL);
  SecCertificateCopyNormalizedSubjectSequence(NULL);
}
  ],[
    PHP_DEFINE(HAVE_SECCERTIFICATECOPYNORMALIZEDISSUERSEQUENCE, 1)
    PHP_DEFINE(HAVE_SECCERTIFICATECOPYNORMALIZEDSUBJECTSEQUENCE, 1)
  ])

  dnl Requires 10.13
  AC_TRY_COMPILE([
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
  ],[
int main(void) {
  SecCertificateCopySerialNumberData(NULL, NULL);
  return 0;
}
  ],[
    PHP_DEFINE(HAVE_SECCERTIFICTECOPYSERIALNUMBERDATA, 1)
  ])

  PHP_ADD_FRAMEWORK(CoreFoundation)
  PHP_ADD_FRAMEWORK(Security)
  PHP_DEFINE(MAC_OS_X_VERSION_MIN_REQUIRED, 101200)
  PHP_REQUIRE_CXX()

  PHP_NEW_EXTENSION(darwin, darwin.cpp security.cpp \
    exception.cpp security-exception.cpp cf-error.cpp \
    sec-keychain.cpp sec-certificate.cpp sec-key.cpp sec-transform.cpp, \
    $ext_shared, , [-std=c++11])
fi
