{-|
Module      : Bindings.LibSodium
Description : Bindings for LibSodium
License     : PublicDomain
Maintainer  : daveparrish@tutanota.com
Stability   : experimental
Portability : POSIX

* <https://github.com/jedisct1/libsodium Source>
* <https://download.libsodium.org/doc/ Documentation>

-}

{-# LANGUAGE ForeignFunctionInterface #-}

#include <bindings.dsl.h>
#include <sodium.h>

module Bindings.LibSodium where
#strict_import

-- | Initializes the Sodium library
-- 
-- <https://download.libsodium.org/doc/usage/ Summary of when to use sodium_init>
#ccall sodium_init, IO CInt
-- |

-- ** Helpers

-- | Constant-time  test for equality
#ccall sodium_memcmp, Ptr () -> Ptr () -> CSize -> IO CInt
-- |

-- *** Hexadecimal encoding/decoding

-- | convert string from binary to hexidecimal
#ccall sodium_bin2hex, Ptr CChar -> CSize -> Ptr () -> CSize -> IO CString
-- |

-- ** Random data

-- | Generate a random byte
#ccall randombytes_random, IO CUInt
-- |
