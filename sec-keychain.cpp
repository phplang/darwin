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

zend_class_entry *SecKeychain_ce = nullptr;

/****************************************************************************/

static PHP_METHOD(SecKeychain, __construct) {
	throw DarwinException(0, "wtf?");
}

#define SECKEYCHAIN(keychain) \
	auto keychain = CFObject::get(Z_OBJ_P(getThis()))->as<SecKeychainRef>(); \
	if (!keychain) { \
		throw DarwinException(0, "Keychain object has no value"); \
	} else do {} while (false)

/* {{{ proto SecKeychain SecKeychian::Create(string $name[, ?string $password = NULL]) */
ZEND_BEGIN_ARG_INFO_EX(seckeychain_create_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKeychain, Create) {
	zend_string *name;
	zend_string *password = nullptr;
	SecKeychainRef keychain;

	if (FAILURE == zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|S!", &name, &password)) {
		return;
	}

	OSStatus status;
	if (password) {
		status = SecKeychainCreate(ZSTR_VAL(name), ZSTR_LEN(password), ZSTR_VAL(password), false, nullptr, &keychain);
	} else {
		status = SecKeychainCreate(ZSTR_VAL(name), 0, nullptr, true, nullptr, &keychain);
	}

	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to create keychain %s", ZSTR_VAL(name));
	}

	RETURN_SECKEYCHAIN(keychain);
}
/* }}} */

/* {{{ proto SecKeychain SecKeychain::Open(string $name) */
ZEND_BEGIN_ARG_INFO_EX(seckeychain_open_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKeychain, Open) {
	zend_string *name;

	if (FAILURE == zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &name)) {
		return;
	}

	SecKeychainRef keychain;
	auto status = SecKeychainOpen(ZSTR_VAL(name), &keychain);
	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to open keychain %s", ZSTR_VAL(name));
	}

	RETURN_SECKEYCHAIN(keychain);
}
/* }}} */

/* {{{ proto this SecKeychain::lock() */
static PHP_METHOD(SecKeychain, lock) {
	if (zend_parse_parameters_none_throw()) { return; }
	SECKEYCHAIN(keychain);

	auto status = SecKeychainLock(keychain);
	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to lock keychain");
	}

	RETURN_ZVAL(getThis(), 1, 0);
}
/* }}} */

/* {{{ proto this SecKeychain::unlock([?string $password = NULL]) */
ZEND_BEGIN_ARG_INFO_EX(seckeychain_unlock_arginfo, 0, ZEND_RETURN_VALUE, 0)
	ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKeychain, unlock) {
	zend_string *password = nullptr;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|S!", &password) == FAILURE) {
		return;
	}
	SECKEYCHAIN(keychain);

	OSStatus status;
	if (password) {
		status = SecKeychainUnlock(keychain, ZSTR_LEN(password), ZSTR_VAL(password), 1);
	} else {
		status = SecKeychainUnlock(keychain, 0, NULL, 0);
	}

	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to unlock keychain");
	}

	RETURN_ZVAL(getThis(), 1, 0);
}
/* }}} */

static PHP_METHOD(SecKeychain, getVersion) {
	if (zend_parse_parameters_none_throw() == FAILURE) { return; }

	uint32_t version;
	OSStatus status = SecKeychainGetVersion(&version);
	if (status != errSecSuccess) {
		throw SecurityException(status, "Unable to determine keychain version");
	}

	RETURN_LONG(version);
}

static zend_function_entry seckeychain_methods[] = {
	/* Create instances via ::Open or ::Create */
	PHP_ME(SecKeychain, __construct, nullptr,
	       ZEND_ACC_CTOR | ZEND_ACC_PRIVATE | ZEND_ACC_FINAL)

	PHP_ME(SecKeychain, Create, seckeychain_create_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(SecKeychain, Open, seckeychain_open_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)

	PHP_ME(SecKeychain, lock, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(SecKeychain, unlock, seckeychain_unlock_arginfo, ZEND_ACC_PUBLIC)

	PHP_ME(SecKeychain, getVersion, nullptr, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)

	PHP_FE_END
};

PHP_MINIT_FUNCTION(darwin_SecKeychain) {
	SecKeychain_ce = CFObject::registerClass(
		INIT_FUNC_ARGS_PASSTHRU,
		"Darwin\\SecKeychain",
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
