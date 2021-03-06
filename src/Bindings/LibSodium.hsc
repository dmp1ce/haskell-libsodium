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

-- | convert string from binary to (little-endian) hexadecimal
#ccall sodium_bin2hex, Ptr CChar -> CSize -> Ptr () -> CSize -> IO CString
-- |

-- | convert string from hexadecimal to binary
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

-- ** Generating random data

-- | Generate a random byte
#ccall randombytes_random, IO CUInt
-- |

-- | Generate a random byte, but it does its best to guarantee a
-- uniform distribution of the possible output values even when
-- upper_bound is not a power of 2.
#ccall randombytes_uniform, CUInt -> IO CUInt
-- |

-- | Fill 'CSize' random bytes starting at 'Ptr' location
#ccall randombytes_buf, Ptr () -> CSize -> IO ()
-- |

{- | 'c'randombytes_close' deallocates the global resources used by the
pseudo-random number generator. More specifically, when the
@\/dev\/urandom@ device is used, it closes the descriptor. Explicitly
calling this function is almost never required. -}
-- '
#ccall randombytes_close, IO CInt
-- |

{- | The 'c'randombytes_stir' function reseeds the pseudo-random number
generator, if it supports this operation. Calling this function is not
required with the default generator, even after a @fork()@ call, unless
the descriptor for @\/dev\/urandom@ was closed using 'c'randombytes_close'. -}
#ccall randombytes_stir, IO ()
-- |

-- ** Secret-key cryptography

-- *** Secret-key authenticated encryption

{- $
Purpose:

1. Encrypt a message with a key and a nonce to keep it confidential
2. Compute an authentication tag. This tag is used to make sure that the message hasn't been tampered with before decrypting it.

A single key is used both to encrypt\/sign and verify\/decrypt messages. For this reason, it is critical to keep the key confidential.

The nonce doesn't have to be confidential, but it should never ever be reused with the same key. The easiest way to generate a nonce is to use 'c'randombytes_buf'.
-}
-- '

-- **** Combined mode

-- | In combined mode, the authentication tag and the encrypted message are stored together. This is usually what you want.
#ccall crypto_secretbox_easy, Ptr CUChar -> Ptr CUChar -> CULLong -> \
  Ptr CUChar -> Ptr CUChar -> IO CInt
-- |

-- | The 'c'crypto_secretbox_open_easy' function verifies and decrypts a ciphertext produced by 'c'crypto_secretbox_easy'.
#ccall crypto_secretbox_open_easy, Ptr CUChar -> Ptr CUChar -> CULLong -> \
  Ptr CUChar -> Ptr CUChar -> IO CInt
-- |

-- **** Detached mode

-- | Some applications may need to store the authentication tag and the encrypted message at different locations.
#ccall crypto_secretbox_detached, Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> \
  CULLong -> Ptr CUChar -> Ptr CUChar -> IO CInt
-- |

-- | The 'c'crypto_secretbox_open_detached' function verifies and decrypts a ciphertext produced by 'c'crypto_secretbox_detached'.
#ccall crypto_secretbox_open_detached, Ptr CUChar -> Ptr CUChar -> \
  Ptr CUChar -> CULLong -> Ptr CUChar -> Ptr CUChar -> IO CInt
-- |


-- **** Constants

#num crypto_secretbox_KEYBYTES
#num crypto_secretbox_MACBYTES
#num crypto_secretbox_NONCEBYTES

-- *** Secret-key authentication

{- $
TODO

https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html
-}

-- *** Authenticated Encryption with Additional Data

{- $
TODO

https://download.libsodium.org/doc/secret-key_cryptography/aead.html
-}

-- ** Public-key cryptography

-- *** Public-key authenticated encryption

{- $
Using public-key authenticated encryption, Bob can encrypt a confidential message specifically for Alice, using Alice's public key.

Using Bob's public key, Alice can verify that the encrypted message was actually created by Bob and was not tampered with, before eventually decrypting it.

Alice only needs Bob's public key, the nonce and the ciphertext. Bob should never ever share his secret key, even with Alice.

And in order to send messages to Alice, Bob only needs Alice's public key. Alice should never ever share her secret key either, even with Bob.

Alice can reply to Bob using the same system, without having to generate a distinct key pair.

The nonce doesn't have to be confidential, but it should be used with just one invocation of c'crypto_box_open_easy for a particular pair of public and secret keys.
-}

-- **** Key pair generation

-- | Randomly generates a secret key and a corresponding public key.
#ccall crypto_box_keypair, Ptr CUChar -> Ptr CUChar -> IO CInt
-- |

-- | Deterministically derive keypair from a single key seed ('c'crypto_box_SEEDBYTES' bytes).
#ccall crypto_box_seed_keypair, Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> \
  IO CInt
-- |

-- | Compute the public key given a secret key previously generated with 'c'crypto_box_keypair'
#ccall crypto_scalarmult_base, Ptr CUChar -> Ptr CUChar -> IO CInt
-- |

-- **** Constants

#num crypto_box_PUBLICKEYBYTES
#num crypto_box_SECRETKEYBYTES
#num crypto_box_MACBYTES
#num crypto_box_NONCEBYTES
#num crypto_box_SEEDBYTES
#num crypto_box_BEFORENMBYTES
