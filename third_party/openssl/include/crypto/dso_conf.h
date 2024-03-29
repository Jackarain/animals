﻿/*
 * Copyright 2016-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_DSO_CONF_H
# define OSSL_CRYPTO_DSO_CONF_H

#if defined(__MINGW64__) || defined(__MINGW32__)
#define DSO_NONE
#define DSO_EXTENSION ".dll"
#else

#ifndef _WIN32
# define DSO_DLFCN
# define HAVE_DLFCN_H
# define DSO_EXTENSION ".so"
#else
# define DSO_EXTENSION ".dll"
# define DSO_NONE
#endif

#endif

#endif
