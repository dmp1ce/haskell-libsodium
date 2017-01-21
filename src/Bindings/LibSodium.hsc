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

-- | Adding large numbers
#ccall sodium_add, Ptr CUChar -> Ptr CUChar -> CSize -> IO ()
-- |

-- *** Comparing large numbers

-- | Comparing large numbers
#ccall sodium_compare, Ptr () -> Ptr () -> CSize -> IO CInt
-- |

-- *** Testing for all zeros

-- | Testing for all zeros
#ccall sodium_is_zero, Ptr CUChar -> CSize -> IO CInt
-- |

-- ** Securing memory allocations

-- *** Zeroing memory

-- | Zeroing memory
#ccall sodium_memzero, Ptr () -> CSize -> IO ()
-- |

-- *** Locking memory

-- | Lock memory
#ccall sodium_mlock, Ptr () -> CSize -> IO CInt
-- |

-- | Unlock memory
#ccall sodium_munlock, Ptr () -> CSize -> IO CInt
-- |

-- *** Guarded heap allocations

-- | Memory allocation
#ccall sodium_malloc, CSize -> IO (Ptr ())
-- |

-- | Memory array allocation
#ccall sodium_allocarray, CSize -> CSize -> IO (Ptr ())
-- |

-- | Free memory allocation
#ccall sodium_free, Ptr () -> IO ()
-- |

-- | No access memory protection
#ccall sodium_mprotect_noaccess, Ptr () -> IO CInt
-- |

-- | Read-only access memory protection
#ccall sodium_mprotect_readonly, Ptr () -> IO CInt
-- |

-- | Read and write access memory protection
#ccall sodium_mprotect_readwrite, Ptr () -> IO CInt
-- |

-- ** Random data

-- | Generate a random byte
#ccall randombytes_random, IO CUInt
-- |
