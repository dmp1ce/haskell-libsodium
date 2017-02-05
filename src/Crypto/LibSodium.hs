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
import Data.Word
import qualified Data.ByteString.Char8 as BS
import System.IO.Unsafe ( unsafePerformIO )

data InitResult = InitSuccess | InitFailure
                | AlreadyInitialized | InitUnknown Int
  deriving (Eq, Show)

data NumCompareResult = NumCompareGreaterThan | NumCompareLessThan
                      | NumCompareEqual | NumCompareUnknown Int
  deriving (Eq, Show)

-- | Pointer with guarded memory allocated by 'sodiumMAlloc'
-- or 'sodiumAllocArray'
newtype GuardedPtr a = GuardedPtr { unGuardedPtr :: ForeignPtr a }

-- | <https://download.libsodium.org/doc/usage/ Documentation on when to use sodium_init>
sodiumInit :: IO InitResult
sodiumInit =
  let mapInit 0    = InitSuccess
      mapInit (-1) = InitFailure
      mapInit 1    = AlreadyInitialized
      mapInit i    = InitUnknown i
  in c'sodium_init >>= return . mapInit . fromEnum

-- ** Helpers
-- *** Constant-time test for equality

-- | Uses 'c'sodium_memcmp' for constant-time test for equality
sodiumMemcmp :: (Storable s) =>  Ptr s -> Ptr s
             -> IO (Either Int Bool) -- ^ 'Int' if an unknown error occured.
sodiumMemcmp p1 p2 = 
  let mapRes 0    = Right True
      mapRes (-1) = Right False
      mapRes i    = Left i
  in do size1 <- peek p1 >>= return . sizeOf
        size2 <- peek p2 >>= return . sizeOf
        if (size1 /= size2)
        then return $ Right False
        else do r <- c'sodium_memcmp (castPtr p1)
                                     (castPtr p2)
                                     (toEnum size1)
                (return . mapRes . fromEnum) r

-- *** Hexadecimal encoding/decoding

-- | Uses 'c'sodium_bin2hex' to convert a 'Storable' into a hexadecimal 'String'
sodiumBin2Hex :: (Storable s) => s -> String
sodiumBin2Hex bits = unsafePerformIO $ do
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

-- *** Incrementing large numbers

-- | Uses 'c'sodium_increment' to increment a 'Int' by one
sodiumIncrement :: Int -> IO Int
sodiumIncrement i = do
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Int)
  withForeignPtr fPtrNum $ \ptrNum -> do
    poke ptrNum i
    c'sodium_increment (castPtr ptrNum) ((toEnum . sizeOf) i)
    peek ptrNum

--- *** Comparing large numbers

-- | Uses 'c'sodium_compare' to compare two 'Int'
sodiumCompare :: Int -> Int -> IO NumCompareResult
sodiumCompare x y =
  let mapRes (-1) = NumCompareLessThan
      mapRes 0    = NumCompareEqual
      mapRes 1    = NumCompareGreaterThan
      mapRes i    = NumCompareUnknown i
  in do fPtrNum1 <- mallocForeignPtr :: IO (ForeignPtr Int)
        fPtrNum2 <- mallocForeignPtr :: IO (ForeignPtr Int)
        withForeignPtr fPtrNum1 $ \ptrNum1 ->
          withForeignPtr fPtrNum2 $ \ptrNum2 -> do
          poke ptrNum1 x
          poke ptrNum2 y
          r <- c'sodium_compare (castPtr ptrNum1) (castPtr ptrNum2)
                           ((toEnum . sizeOf) x)
          (return . mapRes . fromEnum) r

-- *** Adding large numbers

-- | Uses 'c'sodium_add' to add 'Int' to an 'Int'
-- Be careful using this function. Overflow from addition is not checked.
sodiumAdd :: Int -> Int -> IO Int
sodiumAdd x y = do
  fPtrNum1 <- mallocForeignPtr :: IO (ForeignPtr Int)
  fPtrNum2 <- mallocForeignPtr :: IO (ForeignPtr Int)
  withForeignPtr fPtrNum1 $ \ptrNum1 ->
    withForeignPtr fPtrNum2 $ \ptrNum2 -> do
    poke ptrNum1 x
    poke ptrNum2 y
    c'sodium_add (castPtr ptrNum1) (castPtr ptrNum2) ((toEnum . sizeOf) x)
    peek ptrNum1

-- *** Testing for all zeros

-- | Uses 'c'sodium_is_zero' to check for all zeros
sodiumIsZero :: (Storable s) => s
             -> IO (Either Int Bool) -- ^ 'Int' if an unknown error occured.
sodiumIsZero x = do
  let xSize = sizeOf x
  fPtr <- mallocForeignPtrBytes xSize

  withForeignPtr fPtr $ \ptr -> do
    poke ptr x
    r <- c'sodium_is_zero (castPtr ptr) (toEnum xSize)
    return $ case r of
      0 -> Right False
      1 -> Right True
      i -> Left $ fromEnum i

-- ** Securing memory allocations

-- *** Zeroing memory

-- | Uses 'c'sodium_memzero' to zero memory location
sodiumMemZero :: (Storable s) => Ptr s -> IO ()
sodiumMemZero x = do
  sizeOfx <- peek x >>= return . sizeOf
  c'sodium_memzero (castPtr x) (toEnum sizeOfx)

-- *** Locking memory

-- | Uses 'c'sodium_mlock' to prevent memory from being swapped
sodiumMLock :: (Storable s) => Ptr s
            -> IO (Either Int Bool) -- ^ 'False' if lock failed.
                                    -- 'Int' if an unknown error occured.
sodiumMLock x = do
  sizeOfx <- peek x >>= return . sizeOf
  res <- c'sodium_mlock (castPtr x) (toEnum sizeOfx)
  return $ case res of
    0    -> Right True
    (-1) -> Right False
    i    -> Left $ fromEnum i

-- | Uses 'c'sodium_munlock' to prevent allow memory to be swapped again
-- after using 'sodiumMLock'.
sodiumMUnlock :: (Storable s) => Ptr s
              -> IO (Either Int Bool) -- ^ 'False' if unlock failed.
                                      -- 'Int' if an unknown error occured.
sodiumMUnlock x = do
  sizeOfx <- peek x >>= return . sizeOf
  res <- c'sodium_munlock (castPtr x) (toEnum sizeOfx)
  return $ case res of
    0    -> Right True
    (-1) -> Right False
    i    -> Left $ fromEnum i

-- *** Guarded heap allocations

-- | Uses 'c'sodium_malloc' to allocate memory which is protected from
-- overflows
sodiumMAlloc :: Int -- ^ Bytes of memory to allocate
             -> IO (GuardedPtr a)
sodiumMAlloc i = do
  ptr <- c'sodium_malloc (toEnum i)
  newForeignPtr p'sodium_free (castPtr ptr) >>=
    (return . GuardedPtr . castForeignPtr)

-- | Uses 'c'sodium_allocarray' to allocate an array of memory protected from
-- overflows
sodiumAllocArray :: Int -- ^ Bytes of memory to allocate per object
                 -> Int -- ^ Number of objects to allocate
                 -> IO (GuardedPtr a)
sodiumAllocArray i j = do
  ptr <- c'sodium_allocarray (toEnum i) (toEnum j)
  newForeignPtr p'sodium_free (castPtr ptr) >>=
    (return . GuardedPtr . castForeignPtr)

-- | Uses 'c'sodium_free' to deallocate 'GuardedPtr' memory allocated
sodiumFree :: GuardedPtr a -> IO ()
sodiumFree gPtr = finalizeForeignPtr (unGuardedPtr gPtr)

-- | Uses 'c'sodium_mprotect_noaccess' to prevent access to a memory segment
sodiumMProtectNoAccess :: GuardedPtr a -> IO (Either Int Bool)
sodiumMProtectNoAccess gPtr = withForeignPtr (unGuardedPtr gPtr) $ \ptr -> do
  r <- c'sodium_mprotect_noaccess (castPtr ptr)
  return $ case r of
    0 -> Right True
    i -> Left $ fromEnum i

-- | Uses 'c'sodium_mprotect_readonly' to prevent write access
-- to a memory segment
sodiumMProtectReadonly :: GuardedPtr a -> IO (Either Int Bool)
sodiumMProtectReadonly gPtr = withForeignPtr (unGuardedPtr gPtr) $ \ptr -> do
  r <- c'sodium_mprotect_readonly (castPtr ptr)
  return $ case r of
    0 -> Right True
    i -> Left $ fromEnum i

-- | Uses 'c'sodium_mprotect_readwrite' to allow read and write access
-- to a memory segment
sodiumMProtectReadWrite :: GuardedPtr a -> IO (Either Int Bool)
sodiumMProtectReadWrite gPtr = withForeignPtr (unGuardedPtr gPtr) $ \ptr -> do
  r <- c'sodium_mprotect_readwrite (castPtr ptr)
  return $ case r of
    0 -> Right True
    i -> Left $ fromEnum i

-- ** Random data

-- | Uses 'c'randombytes_random' to produce a random 'Word'
randomBytesRandom :: IO Int
randomBytesRandom = (return . fromEnum) =<< c'randombytes_random

-- | Uses 'c'randombytes_uniform' to produce a random 'Int' bounded by 'i'
randomBytesUniform :: Int -> IO Int
randomBytesUniform i = (return . fromEnum) =<<
  c'randombytes_uniform (toEnum i)

-- | Uses 'c'randombytes_buf' to fill a 'Ptr' with random bytes.
-- Uses 'Storable' to determine size of pointer buffer.
randomBytesBuf :: (Storable s) => Ptr s -> IO ()
randomBytesBuf ptr = do
  ptrSize <- peek ptr >>= return . sizeOf
  c'randombytes_buf (castPtr ptr) (toEnum ptrSize)

-- | Uses 'c'randombytes_close' to deallocates the global resources used by
-- the pseudo-random number generator.
randomBytesClose :: IO (Either Int Bool)
randomBytesClose = do
  r <- c'randombytes_close
  return $ case r of
    0 -> Right True
    i -> Left $ fromEnum i

-- | Uses 'c'randombytes_stir' reseeds the pseudo-random number generator,
-- if it supports this operation.
randomBytesStir :: IO ()
randomBytesStir = c'randombytes_stir

-- ** Secret-key authenticated encryption

{- $
Purpose:

1. Encrypt a message with a key and a nonce to keep it confidential
2. Compute an authentication tag. This tag is used to make sure that the message hasn't been tampered with before decrypting it.

A single key is used both to encrypt\/sign and verify\/decrypt messages. For this reason, it is critical to keep the key confidential. Use 'newKey' to generate a new key.

The nonce doesn't have to be confidential, but it should never ever be reused with the same key. Use 'newNonce' to generate a new Nonce.
-}

newtype SecretBoxKey = SecretBoxKey (GuardedPtr [Word8])

newSecretBoxKey :: IO SecretBoxKey
newSecretBoxKey = do
  -- Guard key memory
  gPtrKey <- sodiumMAlloc c'crypto_secretbox_KEYBYTES
  withForeignPtr (unGuardedPtr gPtrKey) $ \ptr ->
    c'randombytes_buf (castPtr ptr) (toEnum c'crypto_secretbox_KEYBYTES)
  return $ SecretBoxKey gPtrKey

newtype SecretBoxNonce = SecretBoxNonce (GuardedPtr [Word8])

newSecretBoxNonce :: IO SecretBoxNonce
newSecretBoxNonce = do
  -- Guard nonce memory
  gPtrKey <- sodiumMAlloc c'crypto_secretbox_NONCEBYTES
  withForeignPtr (unGuardedPtr gPtrKey) $ \ptr ->
    c'randombytes_buf (castPtr ptr) (toEnum c'crypto_secretbox_NONCEBYTES)
  return $ SecretBoxNonce gPtrKey

-- *** Combined mode

-- | In combined mode, the authentication tag and the encrypted message are stored together. This is usually what you want.
cryptoSecretBoxEasy :: BS.ByteString -- ^ Message
                    -> SecretBoxNonce
                    -> SecretBoxKey
                    -> Either Int BS.ByteString
                    -- ^ Cyphertext or error code from
                    -- 'c'crypto_secretbox_easy'
cryptoSecretBoxEasy m (SecretBoxNonce n) (SecretBoxKey k) =
  unsafePerformIO $ do
  -- Determine length of cypher text
  let mlen = BS.length m
      clen = c'crypto_secretbox_MACBYTES + mlen
  fPtrCypher <- mallocForeignPtrBytes (clen)
  -- This message should probably be allocated in guarded memory
  -- with a custom @Guarded@ function
  BS.useAsCString m $ \ptrM ->
    withForeignPtr fPtrCypher $ \ptrCypher ->
      withForeignPtr (unGuardedPtr n) $ \ptrNonce ->
        withForeignPtr (unGuardedPtr k) $ \ptrKey -> do

    retEncrypt <- c'crypto_secretbox_easy ptrCypher (castPtr ptrM) (toEnum mlen) (castPtr ptrNonce) (castPtr ptrKey)

    case retEncrypt of
      0 -> BS.packCStringLen ((castPtr ptrCypher),clen) >>= return . Right
      i -> return $ Left (fromEnum i)

-- The 'cryptoSecretBoxOpenEasy' function verifies and decrypts a ciphertext produced by 'cryptoSecretBoxEasy'.
cryptoSecretBoxOpenEasy :: BS.ByteString -- ^ Cyphertext
                        -> SecretBoxNonce
                        -> SecretBoxKey
                        -> Either Int BS.ByteString
                        -- ^ Message or error code from
                        -- 'c'crypto_secretbox_open_easy'
cryptoSecretBoxOpenEasy c (SecretBoxNonce n) (SecretBoxKey k) =
  unsafePerformIO $ do
  -- Determine length of cyphertext
  let clen = BS.length c
      mlen = clen - c'crypto_secretbox_MACBYTES
  -- This message should probably be allocated in guarded memory
  -- with a custom @Guarded@ function
  fPtrMessage <- mallocForeignPtrBytes (clen)
  withForeignPtr fPtrMessage $ \ptrMessage ->
    BS.useAsCString c $ \ptrC ->
      withForeignPtr (unGuardedPtr n) $ \ptrNonce ->
        withForeignPtr (unGuardedPtr k) $ \ptrKey -> do

    retDecrypt <- c'crypto_secretbox_open_easy ptrMessage (castPtr ptrC)
                  (toEnum clen) (castPtr ptrNonce) (castPtr ptrKey)

    case retDecrypt of
      0 -> BS.packCStringLen ((castPtr ptrMessage), mlen) >>= return . Right
      i -> return $ Left (fromEnum i)
