/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2017 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Sara Golemon <pollita@php.net>                               |
  +----------------------------------------------------------------------+
*/

#include "darwin.h"
#include "zend_exceptions.h"

namespace php { namespace darwin {

zend_class_entry *SecCertificate_ce = nullptr;

/*******************************************************************************/

/* {{{ proto void SecCertificate::__construct() */
static PHP_METHOD(SecCertificate, __construct) {
	throw DarwinException(0, "wtf?");
}
/* }}} */

/* {{{ proto Certificate SecCertificate::CreateFromDER(string $der) */
ZEND_BEGIN_ARG_INFO_EX(cert_createfromder_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_INFO(0, der)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecCertificate, CreateFromDER) {
	zend_string *der;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &der) == FAILURE) {
		return;
	}

	auto data = CFDataCreateWithBytesNoCopy(nullptr, (UInt8*)ZSTR_VAL(der), ZSTR_LEN(der), kCFAllocatorNull);
	if (!data) {
		throw DarwinException(0, "Unable to wrap CFData");
	}

	auto certificate = SecCertificateCreateWithData(nullptr, data);
	CFRelease(data);
	if (!certificate) {
		throw DarwinException(0, "Unable to create certificate from data");
	}

	RETURN_SECCERTIFICATE(certificate);
}
/* }}} */

#define SECCERT(cert) \
	auto cert = CFObject::get(Z_OBJ_P(getThis()))->as<SecCertificateRef>(); \
	if (!cert) { \
		throw DarwinException(0, "Certificate object has no value"); \
	} else do {} while (false)

/* {{{ proto string SecCertificate::getDER() */
static PHP_METHOD(SecCertificate, getDER) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	auto data = SecCertificateCopyData(cert);
	if (!data) {
		throw DarwinException(0, "Unable to read certificate data");
	}

	RETURN_CFDATA(data);
}
/* }}} */

/* {{{ proto string SecCertificate::getSubjectSummary() */
static PHP_METHOD(SecCertificate, getSubjectSummary) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	auto strval = SecCertificateCopySubjectSummary(cert);
	if (!strval) {
		throw DarwinException(0, "Unable to get subject summary");
	}

	RETURN_CFSTRING(strval);
}
/* }}} */

/* {{{ proto string SecCertificate::getCommonName() */
static PHP_METHOD(SecCertificate, getCommonName) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	CFStringRef strval;
	auto status = SecCertificateCopyCommonName(cert, &strval);
	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to get common name");
	}
	RETURN_CFSTRING(strval);
}
/* }}} */

/* {{{ proto array SecCertificate::getEmailAddresses() */
static PHP_METHOD(SecCertificate, getEmailAddresses) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	CFArrayRef addresses;
	auto status = SecCertificateCopyEmailAddresses(cert, &addresses);
	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to get email addresses");
	}

	RETURN_CFARRAY(addresses);
}
/* }}} */

/* {{{ proto ?string SecCertificate::getShortDescription() */
static PHP_METHOD(SecCertificate, getShortDescription) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	auto desc = SecCertificateCopyShortDescription(nullptr, cert, nullptr);
	if (!desc) {
		RETURN_NULL();
	}

	RETURN_CFSTRING(desc);
}
/* }}} */

/* {{{ proto ?string SecCertificate::getLongDescription() */
static PHP_METHOD(SecCertificate, getLongDescription) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	auto desc = SecCertificateCopyLongDescription(nullptr, cert, nullptr);
	if (!desc) {
		RETURN_NULL();
	}

	RETURN_CFSTRING(desc);
}
/* }}} */

#ifdef HAVE_SECCERTIFICATECOPYNORMALIZEDISSUERSEQUENCE
/* {{{ proto string SecCertificate::getNormalizedIssuerSequence() */
static PHP_METHOD(SecCertificate, getNormalizedIssuerSequence) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	auto data = SecCertificateCopyNormalizedIssuerSequence(cert);
	if (!data) {
		throw DarwinException(0, "Unable to get normalized issuer sequence");
	}
	RETURN_CFDATA(data);
}
/* }}} */
#endif

#ifdef HAVE_SECCERTIFICATECOPYNORMALIZEDSUBJECTSEQUENCE
/* {{{ proto string SecCertificate::getNormalizedSubjectSequence() */
static PHP_METHOD(SecCertificate, getNormalizedSubjectSequence) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	auto data = SecCertificateCopyNormalizedSubjectSequence(cert);
	if (!data) {
		throw DarwinException(0, "Unable to get normalized subject sequence");
	}
	RETURN_CFDATA(data);
}
/* }}} */
#endif

/* {{{ proto Key SecCertificate::getPublicKey() */
static PHP_METHOD(SecCertificate, getPublicKey) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

#if TARGET_OS_IPHONE
	auto key = SecCertificateCopyPublicKey(cert);
	if (!key) {
		throw DarwinException(0, "Unable to read public key from certificate");
	}
#elif TARGET_OS_OSX
	SecKeyRef key;
	auto status = SecCertificateCopyPublicKey(cert, &key);
	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to read public key from certificate");
	}
#else
# error Neither OSX to IOS
#endif

	RETURN_SECKEY(key);
}
/* }}} */

/* {{{ proto string SecCertificate::getSerialNumberData() */
static PHP_METHOD(SecCertificate, getSerialNumberData) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

#ifdef HAVE_SECCERTIFICATECOPYSERIALNUMBERDATA
	auto data = SecCertificateCopySerialNumberData(cert, nullptr);
#elif TARGET_OS_IPHONE
	auto data = SecCertificateCopySerialNumber(cert);
#elif TARGET_OS_OSX
	auto data = SecCertificateCopySerialNumber(cert, nullptr);
#else
# error Neither OSX nor IOS
#endif
	if (!data) {
		throw DarwinException(0, "Unable to get serial number data");
	}
	RETURN_CFDATA(data);
}
/* }}} */

/* {{{ proto array SecCertificate::getValues() */
static PHP_METHOD(SecCertificate, getValues) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECCERT(cert);

	CFErrorRef error = nullptr;
	auto dict = SecCertificateCopyValues(cert, nullptr, &error);
	if (!dict) {
		if (error) {
			throw CFErrorException(error);
		} else {
			throw DarwinException(0, "Unable to retreive values from certificate");
		}
	}
	if (error) {
		CFRelease(error);
	}

	RETURN_CFDICTIONARY(dict);
}
/* }}} */

static zend_function_entry seccertificate_methods[] = {
	PHP_ME(SecCertificate, __construct, nullptr, ZEND_ACC_CTOR | ZEND_ACC_PRIVATE | ZEND_ACC_FINAL)

	PHP_ME(SecCertificate, CreateFromDER, cert_createfromder_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(SecCertificate, getDER, nullptr, ZEND_ACC_PUBLIC)

	PHP_ME(SecCertificate, getSubjectSummary, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(SecCertificate, getCommonName, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(SecCertificate, getEmailAddresses, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(SecCertificate, getShortDescription, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(SecCertificate, getLongDescription, nullptr, ZEND_ACC_PUBLIC)
#ifdef HAVE_SECCERTIFICATECOPYNORMALIZEDISSUERSEQUENCE
	PHP_ME(SecCertificate, getNormalizedIssuerSequence, nullptr, ZEND_ACC_PUBLIC)
#endif
#ifdef HAVE_SECCERTIFICATECOPYNORMALIZEDSUBJECTSEQUENCE
	PHP_ME(SecCertificate, getNormalizedSubjectSequence, nullptr, ZEND_ACC_PUBLIC)
#endif
	PHP_ME(SecCertificate, getPublicKey, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(SecCertificate, getSerialNumberData, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(SecCertificate, getValues, nullptr, ZEND_ACC_PUBLIC)

	PHP_FE_END
};

PHP_MINIT_FUNCTION(darwin_SecCertificate) {
	SecCertificate_ce = CFObject::registerClass(
		INIT_FUNC_ARGS_PASSTHRU,
		"Darwin\\SecCertificate",
		seccertificate_methods);

	return SUCCESS;
}

}} // namespace php::darwin
