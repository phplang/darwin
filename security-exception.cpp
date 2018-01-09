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

static zend_class_entry *security_exception_ce = nullptr;

SecurityException::SecurityException(OSStatus status, const char *format, ...):
m_status(status) {
	va_list args;

	va_start(args, format);
	auto len = zend_vspprintf(&m_message, 0, format, args);
	va_end(args);

	// Can other frameworks produce OSStatus codes?
	CFType<CFStringRef> secmsg(SecCopyErrorMessageString(status, nullptr));
	auto *zstr = zend_string_from_CFString(secmsg.get(), false); 
	if (zstr && ZSTR_LEN(zstr)) {
		if (len) { 
			// Two messages, concat them.
			char *str;
			zend_spprintf(&str, 0, "%s: %s", m_message, ZSTR_VAL(zstr));
			efree(m_message);
			m_message = str;
		} else {
			// No local message, use OSStatus as-is
			efree(m_message);
			m_message = estrndup(ZSTR_VAL(zstr), ZSTR_LEN(zstr));
		}       
	} // else use format message as-is

	if (zstr) {
		zend_string_release(zstr);
	}
}

SecurityException::~SecurityException() {
	if (m_message) { efree(m_message); }
}

void SecurityException::throwZendException() const {
	zend_throw_exception(security_exception_ce, m_message, (zend_long)m_status);
}

PHP_MINIT_FUNCTION(darwin_SecurityException) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "Darwin\\SecurityException", nullptr);
	security_exception_ce = zend_register_internal_class_ex(&ce, zend_ce_exception);
	security_exception_ce->ce_flags |= ZEND_ACC_FINAL;

	return SUCCESS;
}

}} // namespace php::darwin
