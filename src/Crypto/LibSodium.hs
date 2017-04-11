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
module Crypto.LibSodium ( InitResult (..)
                        , NumCompareResult (..)
                        , unGuardedPtr
                        , sodiumInit
-- ** Helpers
-- *** Constant-time test for equality
                        , sodiumMemcmp
-- *** Hexadecimal encoding/decoding
                        , sodiumBin2Hex
                        , sodiumHex2Bin
-- *** Incrementing large numbers
                        , sodiumIncrement
--- *** Comparing large numbers
                        , sodiumCompare
-- *** Adding large numbers
                        , sodiumAdd
-- *** Testing for all zeros
                        , sodiumIsZero
-- ** Securing memory allocations
-- *** Zeroing memory
                        , sodiumMemZero
-- *** Locking memory
                        , sodiumMLock
                        , sodiumMUnlock
-- *** Guarded heap allocations
                        , sodiumMAlloc
                        , sodiumAllocArray
                        , sodiumFree
                        , sodiumMProtectNoAccess
                        , sodiumMProtectReadonly
                        , sodiumMProtectReadWrite
-- ** Random data
                        , randomBytesRandom
                        , randomBytesUniform
                        , randomBytesBuf
                        , randomBytesClose
                        , randomBytesStir
-- ** Secret-key cryptography

-- *** Secret-key authenticated encryption

{- |
Purpose:

1. Encrypt a message with a key and a nonce to keep it confidential
2. Compute an authentication tag. This tag is used to make sure that the message
hasn't been tampered with before decrypting it.

A single key is used both to encrypt\/sign and verify\/decrypt messages. For this
reason, it is critical to keep the key confidential. Use 'newSecretBoxKey' to
generate a new key.

The nonce doesn't have to be confidential, but it should never ever be reused with
the same key. Use 'newNonce' to generate a new Nonce.
-}
                        , newSecretBoxKey
                        , newSecretBoxNonce
-- **** Combined mode
                        , cryptoSecretBoxEasy
                        , cryptoSecretBoxOpenEasy
-- **** Detached mode
                        , cryptoSecretBoxDetached
                        , cryptoSecretBoxOpenDetached
-- *** Secret-key authentication

{- |
TODO

https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html
-}

{- |
TODO

https://download.libsodium.org/doc/secret-key_cryptography/aead.html
-}

-- ** Public-key cryptography

-- *** Public-key authenticated encryption

{- |
Using public-key authenticated encryption, Bob can encrypt a confidential message
specifically for Alice, using Alice's public key.

Using Bob's public key, Alice can verify that the encrypted message was actually
created by Bob and was not tampered with, before eventually decrypting it.

Alice only needs Bob's public key, the nonce and the ciphertext. Bob should never
ever share his secret key, even with Alice.

And in order to send messages to Alice, Bob only needs Alice's public key. Alice
should never ever share her secret key either, even with Bob.

Alice can reply to Bob using the same system, without having to generate a distinct
key pair.

The nonce doesn't have to be confidential, but it should be used with just one
invocation of 'cryptoBoxOpenEasy' for a particular pair of public and secret keys.
-}

-- **** Key pair generation
                        , BoxKeypair (BoxKeypair)
                        , cryptoBoxKeypair
                        , cryptoScalarmultBase
                        ) where

import Bindings.LibSodium
import Foreign.Storable
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.C.String
import qualified Data.ByteString.Char8 as BS
import System.IO.Unsafe ( unsafePerformIO )
import Foreign.Marshal.Array

data InitResult = InitSuccess | InitFailure
                | AlreadyInitialized | InitUnknown Int
  deriving (Eq, Show)

data NumCompareResult = NumCompareGreaterThan | NumCompareLessThan
                      | NumCompareEqual | NumCompareUnknown Int
  deriving (Eq, Show)

-- | Pointer with guarded memory allocated by 'sodiumMAlloc'
-- or 'sodiumAllocArray'
newtype GuardedPtr a = GuardedPtr { unGuardedPtr :: ForeignPtr a }

-- | Examines the value in guarded memory space to determine if
-- 'Storable' is 'Eq'
guardedPtrContentsEq :: (Eq a, Storable a)
                     => GuardedPtr a -> GuardedPtr a -> Bool
guardedPtrContentsEq (GuardedPtr fPtrX) (GuardedPtr fPtrY) =
  unsafePerformIO $
    withForeignPtr fPtrX $ \ptrX -> withForeignPtr fPtrY $ \ptrY -> do
      x <- peek ptrX
      y <- peek ptrY
      return $ x == y

-- | <https://download.libsodium.org/doc/usage/ Documentation on when to use sodium_init>
sodiumInit :: IO InitResult
sodiumInit =
  let mapInit 0    = InitSuccess
      mapInit (-1) = InitFailure
      mapInit 1    = AlreadyInitialized
      mapInit i    = InitUnknown i
  in c'sodium_init >>= return . mapInit . fromEnum


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

-- | Uses 'c'sodium_hex2bin' to convert a hexadecimal 'String' to a list of
-- 'CUChar' with the remaining unparsed as a 'String'
sodiumHex2Bin :: String -> ([CUChar], String)
sodiumHex2Bin hex = unsafePerformIO $ do
  let hexLength = length hex
      binMax = (hexLength `div` 2)+1
  fPtrBin <- mallocForeignPtrArray binMax :: IO (ForeignPtr CUChar)
  fPtrBinLen <- mallocForeignPtr :: IO (ForeignPtr CSize)
  fPtrHexEnd <- mallocForeignPtr :: IO (ForeignPtr (Ptr CChar))

  withForeignPtr fPtrBin $ \ptrBin ->
    withCString hex $ \ptrHex ->
      withForeignPtr fPtrBinLen $ \ptrBinLen ->
        withForeignPtr fPtrHexEnd $ \ptrHexEnd -> do

    res <- c'sodium_hex2bin (castPtr ptrBin) (toEnum binMax)
                            ptrHex (toEnum hexLength) nullPtr
                            ptrBinLen ptrHexEnd

    case res of
      0 -> return ()
      i -> error $ "Invalid return: " ++ show i

    --binValue <- peek ptrBin
    binLenValue <- peek ptrBinLen
    binValue    <- peekArray (fromEnum binLenValue) ptrBin
    hexEndValue <- peek ptrHexEnd >>= peekCAString
    return (binValue, hexEndValue)


-- | Uses 'c'sodium_increment' to increment a 'Int' by one
sodiumIncrement :: Int -> IO Int
sodiumIncrement i = do
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Int)
  withForeignPtr fPtrNum $ \ptrNum -> do
    poke ptrNum i
    c'sodium_increment (castPtr ptrNum) ((toEnum . sizeOf) i)
    peek ptrNum


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


-- | Uses 'c'sodium_memzero' to zero memory location
sodiumMemZero :: (Storable s) => Ptr s -> IO ()
sodiumMemZero x = do
  sizeOfx <- peek x >>= return . sizeOf
  c'sodium_memzero (castPtr x) (toEnum sizeOfx)


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

newtype SecretBoxKey = SecretBoxKey (GuardedPtr CUChar)

newSecretBoxKey :: IO SecretBoxKey
newSecretBoxKey = do
  -- Guard key memory
  gPtrKey <- sodiumMAlloc c'crypto_secretbox_KEYBYTES
  withForeignPtr (unGuardedPtr gPtrKey) $ \ptr ->
    c'randombytes_buf (castPtr ptr) (toEnum c'crypto_secretbox_KEYBYTES)
  return $ SecretBoxKey gPtrKey

newtype SecretBoxNonce = SecretBoxNonce (GuardedPtr CUChar)

newSecretBoxNonce :: IO SecretBoxNonce
newSecretBoxNonce = do
  -- Guard nonce memory
  gPtrKey <- sodiumMAlloc c'crypto_secretbox_NONCEBYTES
  withForeignPtr (unGuardedPtr gPtrKey) $ \ptr ->
    c'randombytes_buf (castPtr ptr) (toEnum c'crypto_secretbox_NONCEBYTES)
  return $ SecretBoxNonce gPtrKey


-- | In combined mode, the authentication tag and the encrypted message are stored
-- together. This is usually what you want.
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

-- | The 'cryptoSecretBoxOpenEasy' function verifies and decrypts a ciphertext
-- produced by 'cryptoSecretBoxEasy'.
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


newtype SecretBoxMac = SecretBoxMac (GuardedPtr CUChar)

-- | Examines the value in guarded memory space to determine if Mac is equal
instance Eq SecretBoxMac where
  (SecretBoxMac x) == (SecretBoxMac y) = guardedPtrContentsEq x y

-- | Some applications may need to store the authentication tag and the encrypted
-- message at different locations.
cryptoSecretBoxDetached :: BS.ByteString -- ^ Message
                        -> SecretBoxNonce
                        -> SecretBoxKey
                        -> Either Int (BS.ByteString, SecretBoxMac)
                        -- ^ Cyphertext and Mac or error code from
                        -- 'c'crypto_secretbox_easy'
cryptoSecretBoxDetached m (SecretBoxNonce n) (SecretBoxKey k) =
  unsafePerformIO $ do
  -- Determine length of cypher text
  let mlen = BS.length m
  fPtrCypher <- mallocForeignPtrBytes mlen
  gPtrMac <- sodiumMAlloc c'crypto_secretbox_MACBYTES
  -- This message should probably be allocated in guarded memory
  -- with a custom @Guarded@ function
  BS.useAsCString m $ \ptrM ->
    withForeignPtr fPtrCypher $ \ptrCypher ->
      withForeignPtr (unGuardedPtr gPtrMac) $ \ptrMac ->
        withForeignPtr (unGuardedPtr n) $ \ptrNonce ->
          withForeignPtr (unGuardedPtr k) $ \ptrKey -> do

    retEncrypt <- c'crypto_secretbox_detached ptrCypher ptrMac (castPtr ptrM) 
                  (toEnum mlen) (castPtr ptrNonce) (castPtr ptrKey)

    case retEncrypt of
      0 -> do
             c' <- BS.packCStringLen ((castPtr ptrCypher),mlen)
             return $ Right (c',(SecretBoxMac gPtrMac))
      i -> return $ Left (fromEnum i)

-- | The 'cryptoSecretBoxOpenEasy' function verifies and decrypts a ciphertext
-- produced by 'cryptoSecretBoxEasy'.
cryptoSecretBoxOpenDetached :: BS.ByteString -- ^ Cyphertext
                            -> SecretBoxMac
                            -> SecretBoxNonce
                            -> SecretBoxKey
                            -> Either Int BS.ByteString
                            -- ^ Message or error code from
                            -- 'c'crypto_secretbox_open_easy'
cryptoSecretBoxOpenDetached c (SecretBoxMac mac) (SecretBoxNonce n)
                            (SecretBoxKey k) = unsafePerformIO $ do
  -- Determine length of cyphertext
  let mlen = BS.length c
  -- This message should probably be allocated in guarded memory
  -- with a custom @Guarded@ function
  fPtrMessage <- mallocForeignPtrBytes mlen
  withForeignPtr fPtrMessage $ \ptrMessage ->
    BS.useAsCString c $ \ptrC ->
      withForeignPtr (unGuardedPtr mac) $ \ptrMac ->
        withForeignPtr (unGuardedPtr n) $ \ptrNonce ->
          withForeignPtr (unGuardedPtr k) $ \ptrKey -> do

    retDecrypt <- c'crypto_secretbox_open_detached ptrMessage (castPtr ptrC)
                  ptrMac (toEnum mlen) (castPtr ptrNonce) (castPtr ptrKey)

    case retDecrypt of
      0 -> BS.packCStringLen ((castPtr ptrMessage), mlen) >>= return . Right
      i -> return $ Left (fromEnum i)


newtype BoxSecretKey = BoxSecretKey (GuardedPtr CUChar)
instance Eq BoxSecretKey where
  (BoxSecretKey x) == (BoxSecretKey y) = guardedPtrContentsEq x y
newtype BoxPublicKey = BoxPublicKey (GuardedPtr CUChar)
instance Eq BoxPublicKey where
  (BoxPublicKey x) == (BoxPublicKey y) = guardedPtrContentsEq x y
data BoxKeypair = BoxKeypair BoxSecretKey BoxPublicKey deriving Eq

-- | Uses pseudo randomness to generate 'BoxKeypair'.
cryptoBoxKeypair :: IO (Either Int BoxKeypair)
cryptoBoxKeypair = do
  gPtrSec <- sodiumMAlloc c'crypto_box_SECRETKEYBYTES
  gPtrPub <- sodiumMAlloc c'crypto_box_PUBLICKEYBYTES
  generateKeypair c'crypto_box_keypair gPtrSec gPtrPub

-- | Deterministic function for recreating 'BoxKeypair' from a secret key.
cryptoScalarmultBase :: BoxSecretKey -> Either Int BoxKeypair
cryptoScalarmultBase (BoxSecretKey gPtrSec) = unsafePerformIO $ do
  gPtrPub <- sodiumMAlloc c'crypto_box_PUBLICKEYBYTES
  generateKeypair c'crypto_scalarmult_base gPtrSec gPtrPub

-- | Helper function for creating a 'BoxKeypair'
generateKeypair :: (Ptr CUChar -> Ptr CUChar -> IO CInt)
                -> GuardedPtr CUChar -> GuardedPtr CUChar
                -> IO (Either Int BoxKeypair)
generateKeypair generator gPtrSec gPtrPub =
  withForeignPtr (unGuardedPtr gPtrSec) $ \ptrSec ->
    withForeignPtr (unGuardedPtr gPtrPub) $ \ptrPub -> do
    r <- generator (castPtr ptrPub) (castPtr ptrSec)
    case r of
      0 ->return $ Right $
             BoxKeypair (BoxSecretKey gPtrSec) (BoxPublicKey gPtrPub)
      i -> return $ Left (fromEnum i)
