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

/* SecTransformGetTypeID and SecGroupTransformGetTypeID are missing
 * from the Darwin Security framework, so calling them results in
 * a segfault.  This is generally considered a bad thing.
 *
 * Therefore, this implementation misses out on several affordances. :(
 */
namespace php { namespace darwin {

zend_class_entry *SecTransform_ce = nullptr;

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

/* {{{ proto void SecTransform::__construct() */
static PHP_METHOD(SecTransform, __construct) {
	throw DarwinException(0, "wtf?");
}
/* }}} */

#define SECKEY_FROM(key, src) \
	auto key = CFObject::get(Z_OBJ_P(src))->as<SecKeyRef>(); \
	if (!key) { \
		throw DarwinException(0, "Key object has no value"); \
	} else do {} while (false)

#define SECTRANSFORM(xform) \
	auto xform = CFObject::get(Z_OBJ_P(getThis()))->as<SecTransformRef>(); \
	if (!xform) { \
		throw DarwinException(0, "Transform object has no value"); \
	} else do {} while (false)

/* {{{ do_keycreate - Basic single arg (SecKey) Transform creation */
ZEND_BEGIN_ARG_INFO_EX(sectrans_keycreate_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_TYPE_INFO(0, key, IS_OBJECT, 0)
ZEND_END_ARG_INFO();
enum PubKey { kUsePrivate = false, kUsePublic = true };
template<typename CtorFunc>
void do_keycreate(INTERNAL_FUNCTION_PARAMETERS, CtorFunc ctor, PubKey pubkey = kUsePrivate) {
	zval *zkey;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O", &zkey, SecKey_ce) == FAILURE) {
		return;
	}
	SECKEY_FROM(keyval, zkey);
	CFType<SecKeyRef> key(keyval, CFType<SecKeyRef>::IncRefType::kAddRef);

	if (pubkey == kUsePublic) {
		auto pub = SecKeyCopyPublicKey(key.get());
		if (pub) { key.reset(pub); }
	}

	CFErrorRef error = nullptr;
	auto xform = ctor(key.get(), &error);
	HANDLE_ERROR(!xform, error, "Unable to create transform");

	RETURN_SECTRANSFORM(xform);
}
/* }}} */

/* {{{ proto SecTransform SecTransform::SignTransformCreate(SecKey $key) */
static PHP_METHOD(SecTransform, SignTransformCreate) {
	do_keycreate(INTERNAL_FUNCTION_PARAM_PASSTHRU, SecSignTransformCreate);
}
/* }}} */

/* {{{ proto SecTransform SecTransform::VerifyTransformCreate(SecKey $key, string $signature) */
ZEND_BEGIN_ARG_INFO_EX(sectrans_verifycreate_arginfo, 0, ZEND_RETURN_VALUE, 2)
	ZEND_ARG_TYPE_INFO(0, key, IS_OBJECT, 0)
	ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecTransform, VerifyTransformCreate) {
	zval *zkey;
	zend_string *sig;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "OS", &zkey, SecKey_ce, &sig) == FAILURE) {
		return;
	}

	SECKEY_FROM(keyval, zkey);
	CFType<SecKeyRef> key(keyval, CFType<SecKeyRef>::IncRefType::kAddRef);
	if (auto pub = SecKeyCopyPublicKey(key.get())) { key.reset(pub); }

	CFType<CFDataRef> cfsig(zend_string_to_CFData(sig));

	CFErrorRef error = nullptr;
	auto xform = SecVerifyTransformCreate(key.get(), cfsig.get(), &error);
	HANDLE_ERROR(!xform, error, "Unable to create transform");

	RETURN_SECTRANSFORM(xform);
}
/* }}} */

/* {{{ proto SecTransform SecTransform::EncryptTransformCreate(SecKey $key) */
static PHP_METHOD(SecTransform, EncryptTransformCreate) {
	do_keycreate(INTERNAL_FUNCTION_PARAM_PASSTHRU, SecEncryptTransformCreate, kUsePublic);
}
/* }}} */

/* {{{ proto SecTransform SecTransform::DecryptTransformCreate(SecKey $key) */
static PHP_METHOD(SecTransform, DecryptTransformCreate) {
	do_keycreate(INTERNAL_FUNCTION_PARAM_PASSTHRU, SecDecryptTransformCreate);
}
/* }}} */

/* {{{ proto SecTransform SecTransform::DigestTransformCreate(string $type[, int $length = 0]) */
ZEND_BEGIN_ARG_INFO_EX(sectrans_digestcreate_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecTransform, DigestTransformCreate) {
	zend_string *type;
	zend_long length = 0;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sl", &type, &length) == FAILURE) {
		return;
	}

	CFType<CFStringRef> cftype(zend_string_to_CFString(type));

	CFErrorRef error = nullptr;
	auto xform = SecDigestTransformCreate(cftype.get(), (CFIndex)length, &error);
	HANDLE_ERROR(!xform, error, "Unable to create transform");

	RETURN_SECTRANSFORM(xform);
}
/* }}} */

/* {{{ do_setattr - Set a typed transform attribute */
void do_setattr(INTERNAL_FUNCTION_PARAMETERS, CFTypeID cftype) {
	zend_string *key;
	zval *arg;

	if (FAILURE == zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sz", &key, &arg)) {
		return;
	}
	SECTRANSFORM(xform);

	if (zend_string_equals(key, zstr_kSecTransformInputAttributeName)) {
		throw DarwinException(0, "Don't set kSecTransformInputAttributeName explicitly, "
		                         "pass it to SecTransform::execute()");
	}

	if (zend_string_equals(key, zstr_kSecTransformOutputAttributeName)) {
		throw DarwinException(0, "Don't set kSecTransformOutputAttributeName explicitly, "
		                         "receive it from SecTransform::execute()");
	}

	CFType<CFStringRef> cfkey(zend_string_to_CFString(key));
	CFType<CFTypeRef> cfval(zval_to_CFType(arg, cftype));
	CFErrorRef error = nullptr;
	SecTransformSetAttribute(xform, cfkey.get(), cfval.get(), &error);
	if (error) { throw CFErrorException(error); }

	RETURN_ZVAL(getThis(), 1, 0);
}
/* }}} */

/* {{{ proto this SecTransform::set(name)Attribute(string $key, ztype $value) */
#define SETATTR_IMPL(name, ztype, cftype) \
ZEND_BEGIN_ARG_INFO_EX(sectrans_set##name##_arginfo, 0, ZEND_RETURN_VALUE, 1) \
	ZEND_ARG_TYPE_INFO(0, value, ztype, 0) \
ZEND_END_ARG_INFO(); \
static PHP_METHOD(SecTransform, set##name##Attribute) { \
	do_setattr(INTERNAL_FUNCTION_PARAM_PASSTHRU, k##cftype##TypeID); \
}
SETATTR_IMPL(Boolean, _IS_BOOL, CFBoolean)
SETATTR_IMPL(Int, IS_LONG, CFNumber)
SETATTR_IMPL(Float, IS_DOUBLE, CFNumber)
SETATTR_IMPL(String, IS_STRING, CFString)
SETATTR_IMPL(Data, IS_STRING, CFData)
/* }}} */

/* {{{ proto mixed SecTransform::getAttribute(string $key) */
ZEND_BEGIN_ARG_INFO_EX(sectrans_getattr_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecTransform, getAttribute) {
	zend_string *key;

	if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &key) == FAILURE) {
		return;
	}

	SECTRANSFORM(xform);

	CFType<CFStringRef> cfkey(zend_string_to_CFString(key));
	auto ret = SecTransformGetAttribute(xform, cfkey.get());
	if (!ret) {
		RETURN_NULL();
	}

	RETURN_CFTYPE(ret);
}
/* }}} */

/* {{{ proto mixed SecTransform::execute(string $input) */
ZEND_BEGIN_ARG_INFO_EX(sectrans_execute_arginfo, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_TYPE_INFO(0, input, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_METHOD(SecTransform, execute) {
	zend_string *input;

	if (FAILURE == zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &input)) {
		return;
	}
	SECTRANSFORM(xform);

	CFType<CFDataRef> cfinput(zend_string_to_CFData(input));
	CFErrorRef error = nullptr;
	SecTransformSetAttribute(xform, kSecTransformInputAttributeName, cfinput.get(), &error);
	if (error) { throw CFErrorException(error); }

	CFType<CFTypeRef> ret(SecTransformExecute(xform, &error));
	if (error) { throw CFErrorException(error); }

	RETURN_CFTYPE(ret.release());
}
/* }}} */

static zend_function_entry sectransform_methods[] = {
	PHP_ME(SecTransform, __construct, nullptr, ZEND_ACC_CTOR | ZEND_ACC_PRIVATE | ZEND_ACC_FINAL)

	PHP_ME(SecTransform, SignTransformCreate, sectrans_keycreate_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(SecTransform, VerifyTransformCreate, sectrans_verifycreate_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)

	PHP_ME(SecTransform, EncryptTransformCreate, sectrans_keycreate_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(SecTransform, DecryptTransformCreate, sectrans_keycreate_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)

	PHP_ME(SecTransform, DigestTransformCreate, sectrans_digestcreate_arginfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)

	PHP_ME(SecTransform, setBooleanAttribute, sectrans_setBoolean_arginfo, ZEND_ACC_PUBLIC)
	PHP_ME(SecTransform, setIntAttribute,     sectrans_setInt_arginfo,     ZEND_ACC_PUBLIC)
	PHP_ME(SecTransform, setFloatAttribute,   sectrans_setFloat_arginfo,   ZEND_ACC_PUBLIC)
	PHP_ME(SecTransform, setStringAttribute,  sectrans_setString_arginfo,  ZEND_ACC_PUBLIC)
	PHP_ME(SecTransform, setDataAttribute,    sectrans_setData_arginfo,    ZEND_ACC_PUBLIC)

	PHP_ME(SecTransform, getAttribute, sectrans_getattr_arginfo, ZEND_ACC_PUBLIC)

	PHP_ME(SecTransform, execute, sectrans_execute_arginfo, ZEND_ACC_PUBLIC)

	PHP_FE_END
};

PHP_MINIT_FUNCTION(darwin_SecTransform) {
	SecTransform_ce = CFObject::registerClass(
		INIT_FUNC_ARGS_PASSTHRU,
		"Darwin\\SecTransform",
		sectransform_methods);

	return SUCCESS;
}

}} // namespace php::darwin
