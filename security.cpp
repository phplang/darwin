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

static zend_class_entry *security_ce = nullptr;

#define PHP_DARWIN_LONG(X)
#define PHP_DARWIN_STR(X) \
	zend_string *zstr_##X = nullptr;
# include "security-constants.h"
#undef PHP_DARWIN_STR
#undef PHP_DARWIN_LONG

static zend_function_entry security_methods[] = {
	PHP_FE_END
};

PHP_MINIT_FUNCTION(darwin_Security) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "Darwin\\Security", security_methods);
	security_ce = zend_register_internal_class(&ce);
	security_ce->ce_flags |= ZEND_ACC_EXPLICIT_ABSTRACT_CLASS
	                       | ZEND_ACC_FINAL;

#define PHP_DARWIN_LONG(X) \
	zend_declare_class_constant_long(security_ce, \
		#X, sizeof(#X) - 1, X);
#define PHP_DARWIN_STR(X) { \
	zval cns; \
	if (!(zstr_##X = zend_string_from_CFString(X, true))) { \
		php_error(E_CORE_WARNING, \
		          "Unable to initialize Darwin\\Security constant: " #X); \
	} \
	ZVAL_NEW_STR(&cns, zstr_##X); \
	zend_declare_class_constant(security_ce, \
		#X, sizeof(#X) - 1, &cns); \
}
# include "security-constants.h"
#undef PHP_DARWIN_STR
#undef PHP_DARWIN_LONG

	return SUCCESS;
}

}} // namespace php::darwin
