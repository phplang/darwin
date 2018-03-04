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

#include <sstream>

namespace php { namespace darwin {

static zend_class_entry *security_ce = nullptr;

#define PHP_DARWIN_LONG(X)
#define PHP_DARWIN_STR(X) \
	zend_string *zstr_##X = nullptr;
#define PHP_DARWIN_ATTR(name, type) PHP_DARWIN_STR(name)
# include "security-constants.h"
#undef PHP_DARWIN_ATTR
#undef PHP_DARWIN_STR
#undef PHP_DARWIN_LONG

static CFUniquePtr<CFTypeRef> zval_secattr_to_CFType(zval *value, zend_string* zkey, CFStringRef& key) {
	CFUniquePtr<CFStringRef> cfkey(zend_string_to_CFString(zkey));
#define PHP_DARWIN_LONG(X)
#define PHP_DARWIN_STR(X)
#define PHP_DARWIN_ATTR(name, type) \
	if (!CFStringCompare(cfkey.get(), name, 0)) { \
		key = name; \
		return CFUniquePtr<CFTypeRef>(zval_to_##type(value)); \
	}
# include "security-constants.h"
#undef PHP_DARWIN_ATTR
#undef PHP_DARWIN_STR
#undef PHP_DARWIN_LONG
	return CFUniquePtr<CFTypeRef>();
}

CFMutableDictionaryRef SecAttr_zend_array_to_CFMutableDictionary(
	zend_array *arr,
	std::function<bool(CFMutableDictionaryRef, zend_string*, zval*)> unknown
) {
	CFUniquePtr<CFMutableDictionaryRef> dict(CFDictionaryCreateMutable(nullptr,
		zend_hash_num_elements(arr),
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks));
	zend_string *key;
	zval *val;

	ZEND_HASH_FOREACH_STR_KEY_VAL(arr, key, val) {
		if (!key) {
			throw DarwinException(0, "Invalid numeric attribute key");
		}
		CFStringRef cfkey = nullptr;
		auto cfval = zval_secattr_to_CFType(val, key, cfkey);
		if (!cfkey || !cfval) {
			if (!unknown || !unknown(dict.get(), key, val)) {
				throw DarwinException(0, "Unknown parameter '%s' in params array", ZSTR_VAL(key));
			}
		} else {
			CFDictionaryAddValue(dict.get(), cfkey, cfval.get());
		}
	} ZEND_HASH_FOREACH_END();

	return dict.release();
}

static zend_function_entry security_methods[] = {
	PHP_FE_END
};

void SecAttr_zend_array_check_required_params(zend_array *arr, std::vector<zend_string*> req) {
	std::ostringstream ss;
	ss << "Missing required elements in parameters array: ";
	bool missing = false;

	for (auto* zstr : req) {
		if (!zend_hash_exists(arr, zstr)) {
			if (missing) { ss << ", "; }
			missing = true;
			ss << ZSTR_VAL(zstr);
		}
	}

	if (missing) {
		throw DarwinException(0, "%s", ss.str().c_str());
	}
}

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
#define PHP_DARWIN_ATTR(name, type) PHP_DARWIN_STR(name)
# include "security-constants.h"
#undef PHP_DARWIN_ATTR
#undef PHP_DARWIN_STR
#undef PHP_DARWIN_LONG

	return SUCCESS;
}

}} // namespace php::darwin
