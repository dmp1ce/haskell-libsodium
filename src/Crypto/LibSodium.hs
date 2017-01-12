{-|
Module      : Crypto.LibSodium
Description : Higher level bindings for LibSodium
License     : PublicDomain
Maintainer  : daveparrish@tutanota.com
Stability   : experimental
Portability : POSIX

* <https://github.com/jedisct1/libsodium Source>
* <https://download.libsodium.org/doc/ Documentation>

-}
module Crypto.LibSodium where

import Bindings.LibSodium
import Foreign.Storable
import Foreign.Ptr

data InitResult = InitSuccess | InitFailure | AlreadyInitialized | InitUnknown Int
  deriving (Eq, Show)
data CompareResult = CompareSuccess | CompareFailure | CompareUnknown Int
  deriving (Eq, Show)

-- | <https://download.libsodium.org/doc/usage/ Documentation on when to use sodium_init>
sodiumInit :: IO InitResult
sodiumInit =
  let mapInit 0    = InitSuccess
      mapInit (-1) = InitFailure
      mapInit 1    = AlreadyInitialized
      mapInit i    = InitUnknown i
  in c'sodium_init >>= return . mapInit . fromEnum

-- ** Helpers

-- | Uses 'c'sodium_memcmp' for constant-time test for equality
sodiumMemcmp :: (Storable s) =>  Ptr s -> Ptr s -> IO CompareResult
sodiumMemcmp p1 p2 = 
  let mapRes 0    = CompareSuccess
      mapRes (-1) = CompareFailure
      mapRes i    = CompareUnknown i
  in do v <- peek p1
        r <- c'sodium_memcmp (castPtr p1) (castPtr p2) ((toEnum . sizeOf) v)
        (return . mapRes . fromEnum) r

-- ** Random data

-- | Uses `c'randombytes_random to produce a random `Integer`
randomInteger :: IO Integer
randomInteger = (return . toInteger) =<< c'randombytes_random
