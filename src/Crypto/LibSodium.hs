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

{-# OPTIONS_GHC -Wall #-}
module Crypto.LibSodium where

import Bindings.LibSodium
import Foreign.Storable
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.C.String

data InitResult = InitSuccess | InitFailure | AlreadyInitialized | InitUnknown Int
  deriving (Eq, Show)

data CompareResult = CompareEqual | CompareNotEqual | CompareUnknown Int
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
  let mapRes 0    = CompareEqual
      mapRes (-1) = CompareNotEqual
      mapRes i    = CompareUnknown i
  in do size1 <- peek p1 >>= return . sizeOf
        size2 <- peek p2 >>= return . sizeOf
        if (size1 /= size2)
        then return CompareNotEqual
        else do r <- c'sodium_memcmp (castPtr p1)
                                     (castPtr p2)
                                     (toEnum size1)
                (return . mapRes . fromEnum) r

-- | Uses 'c'sodium_bin2hex' to convert a 'Storable' into a hexadecimal 'String'
sodiumBin2Hex :: (Storable s) => s -> IO String
sodiumBin2Hex bits = do
  fPtrBin <- mallocForeignPtrBytes (sizeOf bits)
  fPtrHex <- mallocForeignPtr :: IO (ForeignPtr CChar)
  withForeignPtr fPtrBin $ \ptrBin -> withForeignPtr fPtrHex $ \ptrHex -> do
    poke ptrBin bits
    binSize <- peek ptrBin >>= return . sizeOf
    let hexSize = binSize * 2 + 1
    c'sodium_bin2hex ptrHex (toEnum hexSize)
                     (castPtr ptrBin) (toEnum binSize) >>=
      peekCAString

-- | Uses 'c'sodium_hex2bin' to convert a hexadecimal 'String' to a 'Storable'
-- Be careful with this function! Some error cases are not checked.
-- Such as invalid hexadecimal values or overflow cases.
sodiumHex2Bin :: (Storable s) => String -> IO s
sodiumHex2Bin hex = do
  let hexLength = length hex
  fPtrBin <- mallocForeignPtrBytes ((hexLength `div` 2)+1)
  fPtrBinLen <- mallocForeignPtr :: IO (ForeignPtr CSize)
  fPtrHexEnd <- mallocForeignPtr :: IO (ForeignPtr (Ptr CChar))

  withForeignPtr fPtrBin $ \ptrBin ->
    withCString hex $ \ptrHex ->
      withForeignPtr fPtrBinLen $ \ptrBinLen ->
        withForeignPtr fPtrHexEnd $ \ptrHexEnd -> do

    binSizeMax <- peek ptrBin >>= return . sizeOf
    _ <- c'sodium_hex2bin (castPtr ptrBin) (toEnum binSizeMax)
                            ptrHex (toEnum hexLength) nullPtr
                            ptrBinLen ptrHexEnd

    binValue <- peek ptrBin
    return binValue

-- | Uses 'c'sodium_increment' to increment a 'Int' by one
sodiumIncrement :: Int -> IO Int
sodiumIncrement i = do
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Int)
  withForeignPtr fPtrNum $ \ptrNum -> do
    poke ptrNum i
    c'sodium_increment (castPtr ptrNum) ((toEnum . sizeOf) i)
    peek ptrNum

-- ** Random data

-- | Uses `c'randombytes_random to produce a random `Integer`
randomInteger :: IO Integer
randomInteger = (return . toInteger) =<< c'randombytes_random
