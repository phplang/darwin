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

#include <exception>
#include <sstream>

namespace php { namespace darwin {

/* All Core Foundation related objects in this extension
 * have the same basic internal structure, and therefore
 * share the same layout and handlers.
 */
static zend_object_handlers darwin_handlers;

zend_object* CFObject::create(zend_class_entry *ce) {
	auto* objval = (CFObject*)ecalloc(1, sizeof(CFObject) +
	                                     zend_object_properties_size(ce));
	auto* zobj = objval->toZendObject();
	zend_object_std_init(zobj, ce);
	zobj->handlers = &darwin_handlers;
	object_properties_init(zobj, ce);
	return zobj;
}

zend_object* CFObject::clone(zval *src) {
	auto* srcval = CFObject::get(Z_OBJ_P(src));
	auto* ce = Z_OBJCE_P(src);
	auto* dst = ce->create_object(ce);
	auto* dstval = CFObject::get(dst);
	if (srcval->data) {
		dstval->data = srcval->data;
		CFRetain(dstval->data);
	}
	zend_objects_clone_members(dst, Z_OBJ_P(src));
	return dst;
}

void CFObject::free(zend_object *obj) {
	auto *objval = CFObject::get(obj);
	if (objval->data) {
		CFRelease(objval->data);
	}
	zend_object_std_dtor(obj);
}

zend_class_entry* CFObject::registerClass(INIT_FUNC_ARGS,
                                          const char *name,
                                          const zend_function_entry *methods,
                                          zend_class_entry *parent,
                                          uint32_t flags) {
	zend_class_entry ce, *ret;

	INIT_CLASS_ENTRY_EX(ce, name, strlen(name), methods);
	ret = zend_register_internal_class_ex(&ce, parent);
	ret->ce_flags |= flags;
	ret->create_object = CFObject::create;

	return ret;
}

void CFObject::initHandlers() {
        memcpy(&darwin_handlers, zend_get_std_object_handlers(),
               sizeof(zend_object_handlers));
        darwin_handlers.offset = XtOffsetOf(CFObject, std);
        darwin_handlers.clone_obj = CFObject::clone;
        darwin_handlers.free_obj = CFObject::free;
}

/*************************************************************************/
// CFNumber

void zval_from_CFNumber(zval *return_value, CFNumberRef num) {
	if (CFNumberIsFloatType(num)) {
		double dval;
		if (CFNumberGetValue(num, kCFNumberDoubleType, &dval)) {
			RETURN_DOUBLE(dval);
		}
	} else {
		int64_t lval;
		if (CFNumberGetValue(num, kCFNumberSInt64Type, &lval)) {
			RETURN_LONG(lval);
		}
	}
	throw DarwinException(0, "Unable to convert CFNumber to zval");
}

CFNumberRef zend_long_to_CFNumber(zend_long lval) {
	int64_t ival = lval;
	return CFNumberCreate(nullptr, kCFNumberSInt64Type, &ival);
}

CFNumberRef double_to_CFNumber(double dval) {
	return CFNumberCreate(nullptr, kCFNumberDoubleType, &dval);
}

CFNumberRef zval_to_CFNumber(zval *value) {
	switch (Z_TYPE_P(value)) {
		case IS_UNDEF:
		case IS_NULL:
		case IS_TRUE:
		case IS_FALSE: {
			int8_t bval = (Z_TYPE_P(value) == IS_TRUE) ? 1 : 0;
			return CFNumberCreate(nullptr, kCFNumberSInt8Type, &bval);
		}
		case IS_LONG:
			return zend_long_to_CFNumber(Z_LVAL_P(value));
		case IS_DOUBLE:
			return double_to_CFNumber(Z_DVAL_P(value));
		case IS_STRING: {
			zend_long lval;
			double dval;
			auto type = is_numeric_str_function(Z_STR_P(value), &lval, &dval);
			if (type == IS_LONG) {
				return zend_long_to_CFNumber(lval);
			} else if (type == IS_DOUBLE) {
				return double_to_CFNumber(dval);
			} // else fallthrough
			break;
		}
	}
	return nullptr;
}

/*************************************************************************/
// CFString

zend_string* zend_string_from_CFString(CFStringRef str, bool persistent) {
	auto *ret = zend_string_alloc(
		CFStringGetMaximumSizeForEncoding(CFStringGetLength(str),
		                                  kCFStringEncodingUTF8) + 1,
		persistent ? 1 : 0
	);

	if (CFStringGetCString(str, ZSTR_VAL(ret), ZSTR_LEN(ret),
	                       kCFStringEncodingUTF8)) {
		ZSTR_LEN(ret) = strlen(ZSTR_VAL(ret));
		return ret;
	} else {
		zend_string_release(ret);
		return nullptr;
	}
}

CFStringRef zend_string_to_CFString(zend_string *str) {
	return CFStringCreateWithBytes(nullptr,
		(UInt8*)ZSTR_VAL(str), ZSTR_LEN(str),
		kCFStringEncodingUTF8, false);
}

CFStringRef zval_to_CFString(zval *pzv) {
	if (Z_TYPE_P(pzv) == IS_STRING) {
		return zend_string_to_CFString(Z_STR_P(pzv));
	}
	zval tmp;
	ZVAL_ZVAL(&tmp, pzv, 1, 0);
	convert_to_string(&tmp);
	auto ret = zend_string_to_CFString(Z_STR(tmp));
	zval_dtor(&tmp);
	return ret;
}

/*************************************************************************/
// CFData

zend_string* zend_string_from_CFData(CFDataRef data) {
	const auto len = CFDataGetLength(data);
	auto *ret = zend_string_alloc(len, 0);
	memcpy(ZSTR_VAL(ret), CFDataGetBytePtr(data), len);
	ZSTR_VAL(ret)[len] = 0;
	ZSTR_LEN(ret) = len;
	return ret;
}

CFDataRef zend_string_to_CFData(zend_string *str) {
	return CFDataCreate(nullptr, (UInt8*)ZSTR_VAL(str), ZSTR_LEN(str));
}

CFDataRef zval_to_CFData(zval *pzv) {
	if (Z_TYPE_P(pzv) == IS_STRING) {
		return zend_string_to_CFData(Z_STR_P(pzv));
	}
	zval tmp;
	ZVAL_ZVAL(&tmp, pzv, 1, 0);
	convert_to_string(&tmp);
	auto ret = zend_string_to_CFData(Z_STR(tmp));
	zval_dtor(&tmp);
	return ret;
}

/*************************************************************************/
// CFArray

#if PHP_VERSION_NUM < 70300
static zend_array* zend_new_array(size_t sz) {
	auto* ret = (zend_array*)ecalloc(1, sizeof(zend_array));
	zend_hash_init(ret, sz, NULL, ZVAL_PTR_DTOR, 0);
	return ret;
}
#endif

zend_array* zend_array_from_CFArray(CFArrayRef arr) {
	CFIndex idx, count = CFArrayGetCount(arr);
	auto* ret = zend_new_array(count);
	for (idx = 0; idx < count; ++idx) {
		zval value;
		zval_from_CFType(&value, CFArrayGetValueAtIndex(arr, idx));
		zend_hash_next_index_insert(ret, &value);
	}
	return ret;
}

/*************************************************************************/
// CFDictionary

static void elem_from_cfelem(const void *key, const void *val, void *ctx) {
	zval value;
	if (CFGetTypeID(key) != CFStringGetTypeID()) {
		/* Either can't cope with the key or the value, give up. */
		return;
	}
	zval_from_CFType(&value, (CFTypeRef)val);

	auto* zkey = zend_string_from_CFString((CFStringRef)key);
	zend_symtable_update((zend_array*)ctx, zkey, &value);
	zend_string_release(zkey);
}

zend_array* zend_array_from_CFDictionary(CFDictionaryRef dict) {
	auto* ret = zend_new_array(CFDictionaryGetCount(dict));
	// TODO: An exception during the callback might... break things.
	CFDictionaryApplyFunction(dict, elem_from_cfelem, ret);
	return ret;
}

/*************************************************************************/
// CFDate

// CFAbsoluteTime is relative to Jan 1 2001 00:00:00 GMT
// Unix Epoch (and thereby DateTime) is relative to Jan 1, 1970 00:00:00 GMT
static constexpr CFAbsoluteTime k20010101_000000_GMT = 978307200;

void zval_from_CFDate(zval *pzv, CFDateRef date) {
	zval fname;
	ZVAL_STRING(&fname, "date_create");

	std::ostringstream ss;
	ss << '@' << (CFDateGetAbsoluteTime(date) + k20010101_000000_GMT);
	zval arg;
	ZVAL_STRING(&arg, ss.str().c_str());

	ZVAL_UNDEF(pzv);
	const auto ret = call_user_function(EG(function_table), nullptr, &fname, pzv, 1, &arg);
	zval_dtor(&arg);
	zval_dtor(&fname);

	if ((ret == FAILURE) || (Z_TYPE_P(pzv) != IS_OBJECT)) {
		zval_dtor(pzv);
		throw DarwinException(0, "Unable to instantiate DateTime object");
	}
}

CFDateRef zval_to_CFDate(zval *value) {
	zval fname, retval;
	ZVAL_STRING(&fname, "date_timestamp_get");
	ZVAL_UNDEF(&retval);

	const auto ret = call_user_function(EG(funciton_table), nullptr, &fname, &retval, 1, value);
	zval_dtor(&fname);

	if ((ret == FAILURE) || (Z_TYPE(retval) != IS_LONG)) {
		zval_dtor(&retval);
		throw DarwinException(0, "Unable to fetch timestamp from DateTime object");
	}

	return CFDateCreate(nullptr, Z_LVAL(retval) - k20010101_000000_GMT);
}

/*************************************************************************/
// CFType

#define X(T) CFTypeID k##T##TypeID;
PHP_DARWINTYPES(X)
#undef X

void zval_from_CFType(zval *pzv, CFTypeRef value) {
	const auto type = CFGetTypeID(value);
#define X(T) \
	if (type == k##T##TypeID) { \
		zval_from_##T(pzv, (T##Ref)value); \
		CFRelease(value); \
		return; \
	}
PHP_DARWINTYPES(X)
#undef X
	throw DarwinException(0, "Unknown Darwin type: %lx", (long)type);
}

CFTypeRef zval_to_CFType(zval *value, CFTypeID type) {
#define X(T) \
	if (type == k##T##TypeID) { \
		return zval_to_##T(value); \
	}
PHP_DARWINTYPES(X)
#undef X
	throw DarwinException(0, "Unknown Darwin type: %lx", (long)type);
}

/*************************************************************************/
// Module Housekeeping

/* Quietly wrap all internal function calls in a try/catch block
 * so that we can throw real C++ exceptions from any Darwin method
 * and have them handled like PHP excetions.
 */
static void (*orig_execute_internal)(INTERNAL_FUNCTION_PARAMETERS);
static void try_catch_execute(INTERNAL_FUNCTION_PARAMETERS) try {
	orig_execute_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU);
} catch (const ZendThrowable& e) {
	e.throwZendException();
} catch (const std::exception& e) {
	zend_throw_exception(zend_ce_exception, e.what(), 0);
} catch (...) {
	zend_throw_exception(zend_ce_exception, "An unknown error occured", 0);
}

static PHP_MINIT_FUNCTION(darwin) {
// A bug in OSX's security framework means that calling SecTransformGetTypeID()
// will result in an immediate segfault.  Don't do it.
#define X(T) k##T##TypeID = (T##GetTypeID == SecTransformGetTypeID) ? ((CFTypeID)-1) : T##GetTypeID();
PHP_DARWINTYPES(X)
#undef X

	CFObject::initHandlers();

	orig_execute_internal = zend_execute_internal ? zend_execute_internal : execute_internal;
	zend_execute_internal = try_catch_execute;

#define X(T) && (SUCCESS == PHP_MINIT(darwin_##T)(INIT_FUNC_ARGS_PASSTHRU))
	return ((SUCCESS == PHP_MINIT(darwin_Exception)(INIT_FUNC_ARGS_PASSTHRU))
		&& (SUCCESS == PHP_MINIT(darwin_Security)(INIT_FUNC_ARGS_PASSTHRU))
		&& (SUCCESS == PHP_MINIT(darwin_SecurityException)(INIT_FUNC_ARGS_PASSTHRU))
PHP_OBJECTDARWINTYPES(X)
		) ? SUCCESS : FAILURE;
#undef X
}

/* {{{ darwin_module_entry
 */
BEGIN_EXTERN_C()
zend_module_entry darwin_module_entry = {
	STANDARD_MODULE_HEADER,
	"darwin",
	NULL, /* functions */
	PHP_MINIT(darwin),
	NULL, /* MSHUTDOWN */
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	NULL, /* MINFO */
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES
};
END_EXTERN_C()
/* }}} */

#ifdef COMPILE_DL_DARWIN
ZEND_GET_MODULE(darwin)
#endif

}} // namespace php::darwin
/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
