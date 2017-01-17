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

-- | Constant-time test for equality
#ccall sodium_memcmp, Ptr () -> Ptr () -> CSize -> IO CInt
-- |

-- *** Hexadecimal encoding/decoding

-- | convert string from binary to hexidecimal
#ccall sodium_bin2hex, Ptr CChar -> CSize -> Ptr () -> CSize -> IO CString
-- |

-- | convert string from hexidecimal to binary
#ccall sodium_hex2bin, Ptr CUChar -> CSize -> \
                       Ptr CChar -> CSize -> \
                       Ptr CChar -> Ptr CSize -> \
                       Ptr (Ptr CChar) -> \
                       IO CInt
-- |

-- *** Incrementing large numbers

-- | Incrementing large numbers
#ccall sodium_increment, Ptr CUChar -> CSize -> IO ()
-- |

-- *** Adding large numbers

-- | Incrementing large numbers
#ccall sodium_add, Ptr CUChar -> Ptr CUChar -> CSize -> IO ()
-- |

-- ** Random data

-- | Generate a random byte
#ccall randombytes_random, IO CUInt
-- |
