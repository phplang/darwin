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

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHmac.h>

namespace php { namespace darwin {

static zend_class_entry *CommonCrypto_ce = nullptr;

#define WRAPPER(type) \
struct type##Wrapper { \
	static constexpr auto len = CC_##type##_DIGEST_LENGTH; \
	static unsigned char* digest(zend_string *src, unsigned char *dest) { \
		return CC_##type(ZSTR_VAL(src), ZSTR_LEN(src), dest); \
	} \
	static constexpr auto hmac = kCCHmacAlg##type; \
}
WRAPPER(MD5);
WRAPPER(SHA1);
WRAPPER(SHA224);
WRAPPER(SHA256);
WRAPPER(SHA384);
WRAPPER(SHA512);
#undef WRAPPER

/* {{{ proto string CommonCrypto::HASH(string $data) */
ZEND_BEGIN_ARG_INFO_EX(cc_hash_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO();
template <typename HashType>
PHP_NAMED_FUNCTION(CommonCrypto_hash) {
	zend_string *data;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &data) == FAILURE) {
		return;
	}

	zend_string *ret = zend_string_alloc(HashType::len, 0);
	if (!HashType::digest(data, (unsigned char*)ZSTR_VAL(ret))) {
		throw DarwinException(0, "Failure generating hash from CommonCrypto");
	}
	ZSTR_VAL(ret)[HashType::len] = 0;
	ZSTR_LEN(ret) = HashType::len;
	RETURN_STR(ret);
}
/* }}} */

/* {{{ proto string CommonCrypto::HASH_hmac(string $data, string $key) */
ZEND_BEGIN_ARG_INFO_EX(cc_hmac_arginfo, 0, ZEND_RETURN_VALUE, 2)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key,  IS_STRING, 0)
ZEND_END_ARG_INFO();
template <typename HashType>
PHP_NAMED_FUNCTION(CommonCrypto_hmac) {
	zend_string *data, *key;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "SS", &data, &key) == FAILURE) {
		return;
	}

	CCHmacContext ctx;
	CCHmacInit(&ctx, HashType::hmac, ZSTR_VAL(key), ZSTR_LEN(key));
	CCHmacUpdate(&ctx, ZSTR_VAL(data), ZSTR_LEN(data));

	zend_string *ret = zend_string_alloc(HashType::len, 0);
	CCHmacFinal(&ctx, ZSTR_VAL(ret));

	ZSTR_VAL(ret)[HashType::len] = 0;
	ZSTR_LEN(ret) = HashType::len;
	RETURN_STR(ret);
}
/* }}} */

static zend_function_entry crypto_methods[] = {
#define HASH_ME(name, algo) \
	ZEND_NAMED_ME(name,        CommonCrypto_hash<algo##Wrapper>, \
	                    cc_hash_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC) \
	ZEND_NAMED_ME(name##_hmac, CommonCrypto_hmac<algo##Wrapper>, \
	                    cc_hmac_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	HASH_ME(md5, MD5)
	HASH_ME(sha1, SHA1)
	HASH_ME(sha224, SHA224)
	HASH_ME(sha256, SHA256)
	HASH_ME(sha384, SHA384)
	HASH_ME(sha512, SHA512)
#undef HASH_ME
	PHP_FE_END
};

PHP_MINIT_FUNCTION(darwin_CommonCrypto) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "Darwin\\CommonCrypto", crypto_methods);
	CommonCrypto_ce = zend_register_internal_class(&ce);
	CommonCrypto_ce->ce_flags |= ZEND_ACC_EXPLICIT_ABSTRACT_CLASS
	                           | ZEND_ACC_FINAL;

	return SUCCESS;
}

}} // namespace php::darwin
