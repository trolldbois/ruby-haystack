

// swig -c++ -I/usr/include/ -I/usr/include/linux -I/usr/include/c++/4.4/tr1/ -I/usr/include/c++/4.4/ -I/usr/include/i386-linux-gnu/ -importall -xml myopenssl.i
// /var/lib/gems/1.8/bin/ffi-gen myopenssl_wrap.xml myopenssl.rb

%module myopenssl

%{
require 'ffi'

module Myopenssl
  extend FFI::Library
  ffi_lib 'Myopenssl'
%}


%{
 #include <openssl/ossl_typ.h>

 #include <openssl/safestack.h>
 #include <openssl/asn1t.h>
 #include <openssl/asn1.h>

 #include <openssl/evp.h>
 #include <openssl/aes.h>
 #include <openssl/rc4.h>
 #include <openssl/blowfish.h>
 #include <openssl/des.h>
 #include <openssl/cast.h>

 #include <openssl/hmac.h>

 #include <openssl/dsa.h>
 #include <openssl/rsa.h>

// not tested
 #include <openssl/engine.h>
 #include <openssl/crypto.h>
%}


%include <openssl/ossl_typ.h>

%include <openssl/safestack.h>

//%define DECLARE_ASN1_ITEM(name) const ASN1_ITEM * name##_it(void);
//%enddef

// #undef DECLARE_ASN1_ITEM
// %define DECLARE_ASN1_ITEM void
// %enddef

 %include <openssl/asn1t.h>
//%undef DECLARE_ASN1_ITEM
//%enddef

 %include <openssl/asn1.h>


%include <openssl/evp.h>
%include <openssl/aes.h>
%include <openssl/rc4.h>
%include <openssl/blowfish.h>
%include <openssl/des.h>
%include <openssl/cast.h>

%include <openssl/hmac.h>

%include <openssl/dsa.h>
%include <openssl/rsa.h>

// not tested
%include <openssl/engine.h>
%include <openssl/crypto.h>

%{
end
%}

