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

zend_class_entry *CFError_ce = nullptr;

void CFErrorException::throwZendException() const {
	CFStringRef cfmessage = CFErrorCopyDescription(m_err);
	zend_string *message = cfmessage ? zend_string_from_CFString(cfmessage, 0) : nullptr;
	zend_object *ex = zend_throw_exception(CFError_ce, message ? ZSTR_VAL(message) : "", CFErrorGetCode(m_err));

	CFRetain(m_err);
	CFObject::get(ex)->data = m_err;

	if (message) {
		zend_string_release(message);
	}
}

/*******************************************************************************/

/* {{{ proto void CFError::__create() */
static PHP_METHOD(CFError, __construct) {
	DarwinException(0, "wtf?").throwZendException();
}
/* }}} */

#define CFERROR(varname) \
	auto varname = CFObject::get(Z_OBJ_P(getThis()))->as<CFErrorRef>(); \
	if (!varname) { \
		throw DarwinException(0, "Invalid Error object"); \
	}

/* {{{ proto ?string CFError::getDomain() */
static PHP_METHOD(CFError, getDomain) {
	CFStringRef domain;

	if (zend_parse_parameters_none_throw()) { return; }
	CFERROR(error);

	domain = CFErrorGetDomain(error);
	if (domain) {
		RETURN_CFSTRING(domain);
	}
}
/* }}} */

/* {{{ proto array CFError::getUserInfo() */
static PHP_METHOD(CFError, getUserInfo) {
	CFDictionaryRef dict;

	if (zend_parse_parameters_none_throw()) { return; }
	CFERROR(error);

	dict = CFErrorCopyUserInfo(error);
	if (dict) {
		RETURN_CFDICTIONARY(dict);
	}
}
/* }}} */

/* {{{ proto ?string CFError::getFailureReason() */
static PHP_METHOD(CFError, getFailureReason) {
	CFStringRef str;

	if (zend_parse_parameters_none_throw()) { return; }
	CFERROR(error);

	str = CFErrorCopyFailureReason(error);
	if (str) {
		RETURN_CFSTRING(str);
	}
}
/* }}} */

/* {{{ proto ?string CFError::getRecoverySuggestion() */
static PHP_METHOD(CFError, getRecoverySuggestion) {
	CFStringRef str;

	if (zend_parse_parameters_none_throw()) { return; }
	CFERROR(error);

	str = CFErrorCopyRecoverySuggestion(error);
	if (str) {
		RETURN_CFSTRING(str);
	}
}
/* }}} */

static zend_function_entry cferror_methods[] = {
	PHP_ME(CFError, __construct, nullptr, ZEND_ACC_CTOR | ZEND_ACC_PRIVATE | ZEND_ACC_FINAL)

	PHP_ME(CFError, getDomain, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(CFError, getUserInfo, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(CFError, getFailureReason, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(CFError, getRecoverySuggestion, nullptr, ZEND_ACC_PUBLIC)

	PHP_FE_END
};

PHP_MINIT_FUNCTION(darwin_CFError) {
	CFError_ce = CFObject::registerClass(
		INIT_FUNC_ARGS_PASSTHRU,
		"Darwin\\CFError",
		cferror_methods,
		zend_ce_exception);

	return SUCCESS;
}

}} // namespace php::darwin

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
