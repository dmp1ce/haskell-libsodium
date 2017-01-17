module HighLevelTests where

import Test.Tasty
import Test.Tasty.HUnit

import Crypto.LibSodium

import Foreign.C.Types
import Foreign.ForeignPtr
--import Foreign.Ptr
import Foreign.Storable
import Data.Bits

hlTests :: [TestTree]
hlTests =
  [ testCase "sodiumInit" test_sodium_init
  , testCase "randomInteger" test_random_integer
  , testCase "sodiumMemcmp" test_sodium_memcmp
  , testCase "sodiumBin2Hex" test_sodiumBin2Hex
  , testCase "sodiumHex2Bin" test_sodiumHex2Bin
  , testCase "sodiumHex2Bin_Bin2Hex" test_sodiumHex2Bin_Bin2Hex
  , testCase "sodiumIncrement" test_sodiumIncrement
  ]

test_sodium_init :: Assertion
test_sodium_init = do
  r <- sodiumInit
  assertBool ("sodiumInit failed with " ++ show r)
             (r == InitSuccess || r == AlreadyInitialized)

-- Mostly checks that `randomInteger` doesn't crash
test_random_integer :: Assertion
test_random_integer = do
  n <- randomInteger 
  assertBool "randomInteger is not negative" (n >= 0)

test_sodium_memcmp :: Assertion
test_sodium_memcmp = do
  fPtr1 <- mallocForeignPtr :: IO (ForeignPtr CInt)
  fPtr2 <- mallocForeignPtr :: IO (ForeignPtr CInt)
  withForeignPtr fPtr1 $ \ptr1 -> withForeignPtr fPtr2 $ \ptr2 -> do
    poke ptr1 1; poke ptr2 2

    -- Compare failure
    r1 <- sodiumMemcmp ptr1 ptr2
    r1 @?= CompareNotEqual

    -- Compare success
    r2 <- sodiumMemcmp ptr2 ptr2
    r2 @?= CompareEqual

test_sodiumBin2Hex :: Assertion
test_sodiumBin2Hex = do
  res <- sodiumBin2Hex ((bit 0) :: Word)
  res @?= "0100000000000000"

test_sodiumHex2Bin :: Assertion
test_sodiumHex2Bin = do
  res <- sodiumHex2Bin "11" :: IO CUInt
  res @?= 17

test_sodiumHex2Bin_Bin2Hex :: Assertion
test_sodiumHex2Bin_Bin2Hex = do
  let hex = "11001cd0fffffffc"
  bin <- sodiumHex2Bin hex :: IO Word
  hexResult <- sodiumBin2Hex bin
  hexResult @?= hex

test_sodiumIncrement :: Assertion
test_sodiumIncrement = do
  let num = 1999000000001
  res <- sodiumIncrement num
  res @?= num + 1
