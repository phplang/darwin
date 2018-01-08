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

#ifndef incl_DARWIN_H
#define incl_DARWIN_H

#include "php_darwin.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <functional>
#include <vector>

namespace php { namespace darwin {

// Mappable primitive types
#define PHP_BASICDARWINTYPES(X) \
	X(CFBoolean) \
	X(CFNumber) \
	X(CFString) \
	X(CFData) \
	X(CFArray) \
	X(CFDictionary) \
	X(CFDate)

// Wrapped PHP objects: Darwin\\X
#define PHP_OBJECTDARWINTYPES(X) \
	X(CFError) \
	X(SecKey) \
	X(SecKeychain) \
	X(SecCertificate) \
	X(SecTransform)

#define PHP_DARWINTYPES(X) \
	PHP_BASICDARWINTYPES(X) \
	PHP_OBJECTDARWINTYPES(X)

#define X(T) extern zend_class_entry *T##_ce;
PHP_OBJECTDARWINTYPES(X)
#undef X

#define X(T) extern CFTypeID k##T##TypeID;
PHP_DARWINTYPES(X)
#undef X

/*************************************************************************/
// C++ exceptions throwable to PHP

class ZendThrowable {
public:
	virtual ~ZendThrowable() = default;
	virtual void throwZendException() const = 0;
};

class DarwinException : public ZendThrowable {
public:
	DarwinException() = delete;
	DarwinException(const DarwinException&) = delete;
	DarwinException(DarwinException&& src) = default;
	DarwinException(zend_long code,
	                const char *format = "", ...) ZEND_ATTRIBUTE_FORMAT(printf, 2, 3);
	~DarwinException() final;

	void throwZendException() const final;
	const char* getMessage() const { return m_message; }
	zend_long getCode() const { return m_code; }
private:
	char *m_message;
	zend_long m_code;
};

class SecurityException : public ZendThrowable {
public:
	SecurityException() = delete;
	SecurityException(const SecurityException&) = delete;
	SecurityException(SecurityException&& src) = default;
	SecurityException(OSStatus code,
	                  const char *format = "", ...) ZEND_ATTRIBUTE_FORMAT(printf, 2, 3);
	~SecurityException() final;

	void throwZendException() const final;
	const char* getMessage() const { return m_message; }
	OSStatus getCode() const { return m_status; }
private:
	char *m_message;
	OSStatus m_status;
};

class CFErrorException : public ZendThrowable {
public:
	CFErrorException(): m_err(nullptr) {}
	CFErrorException(const CFErrorException&) = delete;
	CFErrorException(CFErrorException&& src) { m_err = src.m_err; }

	enum IncRefType { kAddRef = true, kKeepRef = false };
	CFErrorException(CFErrorRef err, IncRefType reftype = kKeepRef): m_err(err) {
		if (reftype == kAddRef) {
			CFRetain(m_err);
		}
	}
	~CFErrorException() final { CFRelease(m_err); }

	void throwZendException() const final;

	CFErrorRef get() const {
		return m_err;
	}
private:
	CFErrorRef m_err;
};

/*************************************************************************/
// General purpose CFType object wrapper

class CFObject {
public:
	static CFObject* Create(CFTypeRef data, zend_class_entry* ce) {
		zval tmp;
		object_init_ex(&tmp, ce);
		auto* ret = CFObject::get(Z_OBJ(tmp));
		CFRetain(data);
		ret->data = data;
		return ret;
	}

	static CFObject* get(zend_object *obj, zend_class_entry *verifyCe = nullptr) {
		if (verifyCe && !instanceof_function(obj->ce, verifyCe)) {
			throw DarwinException(0, "Invalid object type");
		}
		return ((CFObject*)(obj + 1)) - 1;
	}

	zend_object* toZendObject() {
		return ((zend_object*)(this + 1)) - 1;
	}

	template<typename T>
	T as() const {
		return (T)data;
	}

	static zend_class_entry* registerClass(INIT_FUNC_ARGS,
                                          const char *name,
                                          const zend_function_entry *methods,
                                          zend_class_entry *parent = nullptr,
                                          uint32_t flags = ZEND_ACC_FINAL);

	static void initHandlers();

private:
	friend void CFErrorException::throwZendException() const;

	static zend_object* create(zend_class_entry *ce);
	static zend_object* clone(zval *src);
	static void free(zend_object *obj);

	CFTypeRef data;
	zend_object std;
};

/*************************************************************************/
// CoreFoundation

PHP_MINIT_FUNCTION(darwin_cferror);
PHP_MINIT_FUNCTION(darwin_Exception);

template<typename T>
class CFType {
public:
	CFType(): m_px(nullptr) {}
	CFType(const CFType<T>& src) {
		m_px = src.m_px;
		if (m_px) { CFRetain(m_px); }
	}
	CFType(CFType<T>&& src) {
		m_px = src.m_px;
	}
	CFType& operator=(const CFType<T>&) = delete;

	enum IncRefType { kAddRef = true, kKeepRef = false };
	explicit CFType(T px, IncRefType reftype = kKeepRef): m_px(px) {
		if (m_px && (reftype == kAddRef)) {
			CFRetain(m_px);
		}
	}
	~CFType() { if (m_px) { CFRelease(m_px); } }

	T get() const { return m_px; }
	T* byref() { return &m_px; }
	T release() { auto ret = m_px; m_px = nullptr; return ret; }
	void reset(T px, IncRefType incref = kKeepRef) {
		if (m_px) {
			CFRelease(m_px);
		}
		if (px && (incref == kAddRef)) {
			CFRetain(px);
		}
		m_px = px;
	}

	bool operator!() const { return m_px == nullptr; }
	operator bool() const { return m_px != nullptr; }

private:
	T m_px;
};

inline zend_bool zend_bool_from_CFBoolean(CFBooleanRef bval) {
	return (bval == kCFBooleanTrue) ? 1 : 0;
}
inline void zval_from_CFBoolean(zval *pzv, CFBooleanRef bval) {
	ZVAL_BOOL(pzv, zend_bool_from_CFBoolean(bval));
}
inline CFBooleanRef zend_bool_to_CFBoolean(zend_bool bval) {
	return bval ? kCFBooleanTrue : kCFBooleanFalse;
}
inline CFBooleanRef zval_to_CFBoolean(zval *value) {
	return zend_bool_to_CFBoolean(zval_is_true(value));
}

void zval_from_CFNumber(zval *return_value, CFNumberRef num);
CFNumberRef zend_long_to_CFNumber(zend_long lval);
CFNumberRef double_to_CFNumber(double dval);
CFNumberRef zval_to_CFNumber(zval *value);

zend_string* zend_string_from_CFString(CFStringRef str, bool persistent = false);
CFStringRef zend_string_to_CFString(zend_string *str);
CFStringRef zval_to_CFString(zval *value);
inline void zval_from_CFString(zval *pzv, CFStringRef str) {
	ZVAL_STR(pzv, zend_string_from_CFString(str));
}

zend_string* zend_string_from_CFData(CFDataRef str);
CFDataRef zend_string_to_CFData(zend_string *str);
CFDataRef zval_to_CFData(zval *value);
inline void zval_from_CFData(zval *pzv, CFDataRef str) {
	ZVAL_STR(pzv, zend_string_from_CFData(str));
}

zend_array* zend_array_from_CFArray(CFArrayRef dict);
inline void zval_from_CFArray(zval *pzv, CFArrayRef dict) {
	ZVAL_ARR(pzv, zend_array_from_CFArray(dict));
}
inline CFArrayRef zval_to_CFArray(zval *pzv) {
	throw DarwinException(0, "zval_to_CFArray() makes no sense");
}

zend_array* zend_array_from_CFDictionary(CFDictionaryRef dict);
inline void zval_from_CFDictionary(zval *pzv, CFDictionaryRef dict) {
	ZVAL_ARR(pzv, zend_array_from_CFDictionary(dict));
}
inline CFArrayRef zval_to_CFDictionary(zval *pzv) {
	throw DarwinException(0, "zval_to_CFDictionary() makes no sense");
}

void zval_from_CFDate(zval *pzv, CFDateRef date);
CFDateRef zval_to_CFDate(zval* pzv);

#define X(T) \
inline void zval_from_##T(zval *pzv, T##Ref value) { \
	ZVAL_OBJ(pzv, CFObject::Create(value, T##_ce)->toZendObject()); \
} \
inline zend_object* zend_object_from_##T(T##Ref value) { \
	zval tmp; \
	zval_from_##T(&tmp, value); \
	return Z_OBJ(tmp); \
} \
inline T##Ref zend_object_to_##T(zend_object *obj) { \
	return CFObject::get(obj, T##_ce)->as<T##Ref>(); \
} \
inline T##Ref zval_to_##T(zval* pzv) { \
	if (!pzv || (Z_TYPE_P(pzv) != IS_OBJECT)) { \
		throw DarwinException(0, "Variable is not an object"); \
	} \
	return zend_object_to_##T(Z_OBJ_P(pzv)); \
}
PHP_OBJECTDARWINTYPES(X)
#undef X

void zval_from_CFType(zval *pzv, CFTypeRef value);
CFTypeRef zval_to_CFType(zval *value, CFTypeID type);

#define RETURN_CFBOOLEAN(cfbool) do { zval_from_CFBoolean(return_value, cfbool); return; } while (false)
#define RETURN_CFNUMBER(cfnum) do { zval_from_CFNumber(return_value, cfnum); return; } while (false)
#define RETURN_CFSTRING(cfstr) do { zval_from_CFString(return_value, cfstr); return; } while (false)
#define RETURN_CFDATA(cfdata) do { zval_from_CFData(return_value, cfdata); return; } while (false)
#define RETURN_CFARRAY(cfarray) do { zval_from_CFArray(return_value, cfarray); return; } while (false)
#define RETURN_CFDICTIONARY(cfdict) do { zval_from_CFDictionary(return_value, cfdict); return; } while (false)
#define RETURN_CFTYPE(cftype) do { zval_from_CFType(return_value, cftype); return; } while (false)

/**********************************************************************/
// Security

PHP_MINIT_FUNCTION(darwin_Security);
CFType<CFMutableDictionaryRef> SecAttr_zend_array_to_CFMutableDictionary(
	zend_array *arr,
	std::function<bool(CFMutableDictionaryRef, zend_string*, zval*)> unknown = nullptr
);
void SecAttr_zend_array_check_required_params(zend_array *arr, std::vector<zend_string*> req);

PHP_MINIT_FUNCTION(darwin_SecurityException);
#define X(T) PHP_MINIT_FUNCTION(darwin_##T);
PHP_OBJECTDARWINTYPES(X)
#undef X

PHP_MINIT_FUNCTION(darwin_SecTransform);

#define RETURN_SECKEY(val) do { zval_from_SecKey(return_value, val); return; } while (false)
#define RETURN_SECKEYCHAIN(val) do { zval_from_SecKeychain(return_value, val); return; } while (false)
#define RETURN_SECCERTIFICATE(val) do { zval_from_SecCertificate(return_value, val); return; } while (false)
#define RETURN_SECTRANSFORM(val) do { zval_from_SecTransform(return_value, val); return; } while (false)

#define PHP_DARWIN_LONG(X)
#define PHP_DARWIN_STR(X) \
	extern zend_string *zstr_##X;
#define PHP_DARWIN_ATTR(name, type) PHP_DARWIN_STR(name)
# include "security-constants.h"
#undef PHP_DARWIN_ATTR
#undef PHP_DARWIN_STR
#undef PHP_DARWIN_LONG

}} // namesapce php::darwin

#endif	/* incl_DARWIN_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
