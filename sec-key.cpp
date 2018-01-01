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

zend_class_entry *SecKey_ce = nullptr;

/* We probably don't need to check cond *AND* error
 * but belts and suspenders...
 */
#define HANDLE_ERROR(cond, error, msg) \
        if (cond) { \
                if (error) { \
			throw CFErrorException(error); \
                } \
                throw DarwinException(noErr, msg); \
        } \
        if (error) { CFRelease(error); error = NULL; }

/*******************************************************************************/

/* {{{ proto void SecKey::__create() */
static PHP_METHOD(SecKey, __construct) {
	zend_throw_exception(zend_ce_error_exception, "wtf?", 0);
}
/* }}} */

#define VERIFY_KEY(key) \
	if (!key) { \
		throw DarwinException(0, "Key object has no value"); \
	} else do {} while (false)

#define SECKEY_FROM(key, src) \
	auto key = CFObject::get(Z_OBJ_P(src))->as<SecKeyRef>(); \
	VERIFY_KEY(key)

#define SECKEY(key) SECKEY_FROM(key, getThis())

/* OSX specific APIs, iOS has different APIs... */
#if SEC_OS_OSX
static void marshal_keygen_param(CFMutableDictionaryRef dict,
                                 CFStringRef cfkey,
                                 CFTypeID cftype,
                                 zend_array *container,
                                 zend_string *key,
                                 bool required) {
	auto* value = zend_symtable_find(container, key);
	if (!value) {
		if (required) {
			throw DarwinException(0, "Missing element '%s' from keygen params", ZSTR_VAL(key));
		}
		return;
	}

	CFType<CFTypeRef> cfval(zval_to_CFType(value, cftype));
	if (!cfval) {
		throw DarwinException(0, "Invalid type supplied for KeyGen element '%s'", ZSTR_VAL(key));
	}

	CFDictionaryAddValue(dict, cfkey, cfval.get());
}

#define MARSHAL_KEYGEN_PARAM(ret, key, type, container, req) \
	marshal_keygen_param(ret.get(), key, k##type##TypeID, container, zstr_##key, req)

/* {{{ marshal_symmetric_keygen_params */
static CFType<CFMutableDictionaryRef> marshal_symmetric_keygen_params(zend_array *params) {
	CFType<CFMutableDictionaryRef> ret(CFDictionaryCreateMutable(nullptr,
		zend_hash_num_elements(params),
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks));

	/* Required elements */
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrKeyType, CFString, params, true);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrKeySizeInBits, CFNumber, params, true);

	/* Immediately store key in keychain */
	MARSHAL_KEYGEN_PARAM(ret, kSecUseKeychain, SecKeychain, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrLabel, CFString, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrApplicationLabel, CFString, params, false);

	/* Access Control Settings */
	// TODO: MARSHAL_KEYGEN_PARAM(ret, kSecAttrAccess, SecAccessGetTypeID(), params, 0);

	/* Usage */
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanEncrypt, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanDecrypt, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanWrap, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanUnwrap, CFBoolean, params, false);

	return ret;
}
/* }}} */

/* {{{ proto SecKey SecKey::GenerateSymmetric(array $params) */
ZEND_BEGIN_ARG_INFO_EX(seckey_gensym_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKey, GenerateSymmetric) {
	zend_array *params;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "h", &params) == FAILURE) {
		return;
	}

	auto dict = marshal_symmetric_keygen_params(params);

	CFErrorRef error = nullptr;
	auto key = SecKeyGenerateSymmetric(dict.get(), &error);
	HANDLE_ERROR(!key, error, "Unable to generate symmetric key");

	RETURN_SECKEY(key);
}
/* }}} */

/* {{{ proto SecKey SecKey::DeriveFromPassword(string $password, array $params) */
ZEND_BEGIN_ARG_INFO_EX(seckey_passwd_arginfo, 0, ZEND_RETURN_VALUE, 2)
	ZEND_ARG_INFO(0, password)
	ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKey, DeriveFromPassword) {
	zend_string *password;
	zend_array *params;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sh", &password, &params) == FAILURE) {
		return;
	}

	CFErrorRef error = nullptr;
	CFType<CFStringRef> cfpassword(zend_string_to_CFString(password));
	HANDLE_ERROR(!cfpassword, error, "Unable to translate password");

	auto dict = marshal_symmetric_keygen_params(params);
	MARSHAL_KEYGEN_PARAM(dict, kSecAttrSalt, CFData, params, true);
	MARSHAL_KEYGEN_PARAM(dict, kSecAttrPRF, CFString, params, true);
	MARSHAL_KEYGEN_PARAM(dict, kSecAttrRounds, CFNumber, params, true);

	auto key = SecKeyDeriveFromPassword(cfpassword.get(), dict.get(), &error);
	HANDLE_ERROR(!key, error, "Unable to generate symmetric key");

	RETURN_SECKEY(key);
}
/* }}} */
#endif /* SEC_OS_OSX */

/* {{{ marshal_keygen_params */
static CFType<CFMutableDictionaryRef> marshal_keygen_params(zend_array *params, bool top) {
	CFType<CFMutableDictionaryRef> ret(CFDictionaryCreateMutable(nullptr,
		zend_hash_num_elements(params) + 1, /* Extra space for isPermanent */
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks));

	if (top) {
		MARSHAL_KEYGEN_PARAM(ret, kSecAttrKeyType, CFString, params, true);
		MARSHAL_KEYGEN_PARAM(ret, kSecAttrKeySizeInBits, CFNumber, params, true);
		MARSHAL_KEYGEN_PARAM(ret, kSecAttrTokenID, CFString, params, false);
	}

	MARSHAL_KEYGEN_PARAM(ret, kSecAttrLabel, CFString, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrApplicationTag, CFString, params, false);

	/* Immediately store key in keychain */
	if (zend_symtable_exists(params, zstr_kSecUseKeychain)) {
		CFDictionaryAddValue(ret.get(), kSecAttrIsPermanent, kCFBooleanTrue);
		MARSHAL_KEYGEN_PARAM(ret, kSecUseKeychain, SecKeychain, params, true);
	}

	/* Usage */
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanEncrypt, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanDecrypt, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanDerive, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanSign, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanVerify, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanWrap, CFBoolean, params, false);
	MARSHAL_KEYGEN_PARAM(ret, kSecAttrCanUnwrap, CFBoolean, params, false);

	if (top) {
		zval *priv = zend_symtable_find(params, zstr_kSecPrivateKeyAttrs);
		zval *pub = zend_symtable_find(params, zstr_kSecPublicKeyAttrs);

		if (priv && (Z_TYPE_P(priv) == IS_ARRAY)) {
			auto dict = marshal_keygen_params(Z_ARR_P(priv), false);
			CFDictionaryAddValue(ret.get(), kSecPrivateKeyAttrs, dict.get());
		}
		if (pub && (Z_TYPE_P(pub) == IS_ARRAY)) {
			auto dict = marshal_keygen_params(Z_ARR_P(pub), false);
			CFDictionaryAddValue(ret.get(), kSecPublicKeyAttrs, dict.get());
		}
	}

	return ret;
}

/* {{{ proto SecKey SecKey::CreateRandomKey(array $params) */
ZEND_BEGIN_ARG_INFO_EX(key_createrandomkey_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKey, CreateRandomKey) {
	zend_array *params;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "h", &params) == FAILURE) {
		return;
	}

	auto dict = marshal_keygen_params(params, true);

	CFErrorRef error = nullptr;
	auto key = SecKeyCreateRandomKey(dict.get(), &error);
	HANDLE_ERROR(!key, error, "Unable to generate key pair");

	RETURN_SECKEY(key);
}
/* }}} */

/* {{{ proto string SecKey::getBlockSize() */
static PHP_METHOD(SecKey, getBlockSize) {
	if (zend_parse_parameters_none_throw()) { return; }

	SECKEY(key);
	RETURN_LONG(SecKeyGetBlockSize(key));
}
/* }}} */

/* {{{ proto SecKey SecKey::getPublicKey() */
static PHP_METHOD(SecKey, getPublicKey) {
	if (zend_parse_parameters_none_throw()) { return; }

	SECKEY(key);
	auto pubkey = SecKeyCopyPublicKey(key);
	if (!pubkey) { RETURN_NULL(); }

	RETURN_SECKEY(pubkey);
}
/* }}} */

#if SEC_OS_OSX
/* {{{ marshal_wrap_params */
static CFType<CFMutableDictionaryRef> marshal_wrap_params(zend_array *params) {
	CFType<CFMutableDictionaryRef> ret(CFDictionaryCreateMutable(nullptr,
		zend_hash_num_elements(params),
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks));

	MARSHAL_KEYGEN_PARAM(ret, kSecAttrSalt, CFData, params, true);

	return ret;
}
/* }}} */

/* {{{ proto string SecKey::wrapKey(SecKey $keyToWrap, array $params) */
ZEND_BEGIN_ARG_INFO_EX(seckey_wrapsym_arginfo, 0, ZEND_RETURN_VALUE, 2)
	ZEND_ARG_INFO(0, keyToWrap)
	ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKey, wrapSymmetric) {
	zval *keyToWrap;
	zend_array *params;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Oh",
	                                &keyToWrap, SecKey_ce,
	                                &params) == FAILURE) {
		return;
	}

	auto dict = marshal_wrap_params(params);

	SECKEY(key);
	SECKEY_FROM(wrapKey, keyToWrap);

	CFErrorRef error = nullptr;
	auto ret = SecKeyWrapSymmetric(wrapKey, key, dict.get(), &error);
	HANDLE_ERROR(!ret, error, "Unable to wrap key");

	RETURN_CFDATA(ret);
}
/* }}} */

/* {{{ proto string SecKey::unwrapKey(string $wrappedKey, array $params) */
ZEND_BEGIN_ARG_INFO_EX(seckey_unwrapsym_arginfo, 0, ZEND_RETURN_VALUE, 2)
	ZEND_ARG_INFO(0, wrappedKey)
	ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecKey, unwrapSymmetric) {
	zend_string *wrappedKey;
	zend_array *params;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Sh", &wrappedKey, &params) == FAILURE) {
		return;
	}

	SECKEY(key);
	CFType<CFDataRef> data(zend_string_to_CFData(wrappedKey));
	auto dict = marshal_wrap_params(params);

	CFErrorRef error = nullptr;
	auto ret = SecKeyUnwrapSymmetric(data.byref(), key, dict.get(), &error);
	HANDLE_ERROR(!ret, error, "Unable to unwrap key");

	RETURN_SECKEY(ret);
}
/* }}} */
#endif /* SEC_OS_OSX */

static zend_function_entry seckey_methods[] = {
	PHP_ME(SecKey, __construct, nullptr, ZEND_ACC_CTOR | ZEND_ACC_PRIVATE | ZEND_ACC_FINAL)

#if SEC_OS_OSX
	PHP_ME(SecKey, GenerateSymmetric, seckey_gensym_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(SecKey, DeriveFromPassword, seckey_passwd_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
#endif

	PHP_ME(SecKey, CreateRandomKey, key_createrandomkey_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)

	PHP_ME(SecKey, getBlockSize, nullptr, ZEND_ACC_PUBLIC)
	PHP_ME(SecKey, getPublicKey, nullptr, ZEND_ACC_PUBLIC)

#if SEC_OS_OSX
	PHP_ME(SecKey, wrapSymmetric, seckey_wrapsym_arginfo, ZEND_ACC_PUBLIC)
	PHP_ME(SecKey, unwrapSymmetric, seckey_unwrapsym_arginfo, ZEND_ACC_PUBLIC)
#endif

	PHP_FE_END
};

PHP_MINIT_FUNCTION(darwin_SecKey) {
	SecKey_ce = CFObject::registerClass(
		INIT_FUNC_ARGS_PASSTHRU,
		"Darwin\\SecKey",
		seckey_methods);

	return SUCCESS;
}

}} // namespace php::darwin
