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
