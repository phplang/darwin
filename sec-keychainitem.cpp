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

namespace php { namespace darwin {

zend_class_entry *SecKeychainItem_ce = nullptr;

/****************************************************************************/

static PHP_METHOD(SecKeychainItem, __construct) {
	throw DarwinException(0, "wtf?");
}

#define SECKEYCHAINITEM(item) \
	auto item = CFObject::get(Z_OBJ_P(getThis()))->as<SecKeychainItemRef>(); \
	if (!item) { \
		throw DarwinException(0, "Keychain item object has no value"); \
	} else do {} while (false)

/* {{{ SecKeychainItem::Create(string $password, array $params) */
ZEND_BEGIN_ARG_INFO_EX(ski_create_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKeychainItem, Create) {
	zend_array *params;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "h", &params) == FAILURE) {
		return;
	}

	CFUniquePtr<CFDictionaryRef> dict(SecAttr_zend_array_to_CFMutableDictionary(params,
		[params](CFMutableDictionaryRef dict, zend_string *key, zval *value) {
			// kSecValueData always takes CFData of the thing's underlying representation.
			// kSecValueRef takes an object instance.
			const bool isRef = zend_string_equals(key, zstr_kSecValueRef);
			if (!isRef && !zend_string_equals(key, zstr_kSecValueData)) { return false; }

			zval *cls = zend_symtable_find(params, zstr_kSecClass);
			if (!cls || (Z_TYPE_P(cls) != IS_STRING)) {
				throw DarwinException(0, "kSecClass must be a string property");
			}
			auto *clsstr = Z_STR_P(cls);
			CFUniquePtr<CFTypeRef> cfval;
			if (!isRef) {
				cfval.reset(zval_to_CFData(value));
			} else {
				if (zend_string_equals(clsstr, zstr_kSecClassGenericPassword) ||
				    zend_string_equals(clsstr, zstr_kSecClassInternetPassword)) {
					cfval.reset(zval_to_SecKeychainItem(value));
				} else if (zend_string_equals(clsstr, zstr_kSecClassCertificate)) {
					cfval.reset(zval_to_SecCertificate(value));
				} else if (zend_string_equals(clsstr, zstr_kSecClassKey)) {
					cfval.reset(zval_to_SecKey(value));
				} else if (zend_string_equals(clsstr, zstr_kSecClassIdentity)) {
					// TODO: SecIdentityRef
				}
			}
			if (!cfval) { return false; }
			CFDictionaryAddValue(dict, isRef ? kSecValueRef : kSecValueData, cfval.get());
			return true;
		}
	));

	CFTypeRef item = nullptr;
	auto status = SecItemAdd(dict.get(), &item);
	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to create keychain item");
	}

	// Ordinarily, RETURN_CFTYPE() takes ownership of the CFTypeRef,
	// but in this case, we don't actually HAVE ownership to give.
	// Explicitly retain a reference in this special case.
	CFRetain(item);
	RETURN_CFTYPE(item);
}
/* }}} */

/* {{{ proto mixed SecKeychainItem::Find(array $params) */
ZEND_BEGIN_ARG_INFO_EX(ski_find_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKeychainItem, Find) {
	zend_array *params;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "h", &params) == FAILURE) {
		return;
	}

	CFUniquePtr<CFDictionaryRef> dict(SecAttr_zend_array_to_CFMutableDictionary(params));

	CFTypeRef item = nullptr;
	auto status = SecItemCopyMatching(dict.get(), &item);
	if (status == errSecSuccess) {
		RETURN_CFTYPE(item);
	}

	if (status == errSecItemNotFound) {
		RETURN_NULL();
	}

	throw SecurityException(status, "Unable to query keychain");
}
/* }}} */

static zend_function_entry seckeychain_methods[] = {
	/* Create instances via ::Open or ::Create */
	PHP_ME(SecKeychainItem, __construct, nullptr,
	       ZEND_ACC_CTOR | ZEND_ACC_PRIVATE | ZEND_ACC_FINAL)

	PHP_ME(SecKeychainItem, Create, ski_create_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(SecKeychainItem, Find, ski_find_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)

	PHP_FE_END
};

PHP_MINIT_FUNCTION(darwin_SecKeychainItem) {
	SecKeychainItem_ce = CFObject::registerClass(
		INIT_FUNC_ARGS_PASSTHRU,
		"Darwin\\SecKeychainItem",
		seckeychain_methods);

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
