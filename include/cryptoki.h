// this file is derived from Mastercard's pkcs11-tools project which is
// itself derived from the RSA Security Inc. PKCS #11 Cryptographic Token
// Interface (Cryptoki). Original source can be found here:
//
// https://github.com/Mastercard/pkcs11-tools/blob/master/include/cryptoki/cryptoki.h

// Relevant licenses below:

/*
 * Copyright (c) 2018 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

#ifndef CRYPTOKI_H
#define CRYPTOKI_H

#define CK_PTR *

#ifdef _MSC_VER
#if defined(_WIN32)
#ifdef _DLL
/* Win32, DLL build */
#define CK_DEFINE_FUNCTION(returnType, name) \
    returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType __declspec(dllimport) (* name)
#else
/* Win32, not DLL build */
#define CK_DEFINE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)
#else
#error "Unsupported platform"
#endif
#else
#define CK_DEFINE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)
#endif

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#if defined(_WIN32)
#pragma pack(push, cryptoki, 1)
#endif

#include "pkcs11.h"

#if defined(_WIN32)
#pragma pack(pop, cryptoki)
#endif

#endif /* CRYPTOKI_H */
