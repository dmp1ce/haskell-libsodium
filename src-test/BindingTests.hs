module BindingTests where

import Test.Tasty
import Test.Tasty.HUnit

import Bindings.LibSodium

import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.C.String
import Foreign.Storable
import Foreign.Ptr

bindingTests :: [TestTree]
bindingTests =
  [ testCase "c'randombytes_random" test_c'randombytes_random
  , testCase "c'sodium_init" test_c'sodium_init
  , testCase "c'sodium_memcmp" test_c'sodium_memcmp
  ]

-- Mostly checking that bindings don't crash 

test_c'sodium_init :: Assertion
test_c'sodium_init = do
  n <- c'sodium_init
  assertBool ("c'sodium_init failed with " ++ show n) (n == 0 || n == 1)

test_c'randombytes_random :: Assertion
test_c'randombytes_random = do
  n <- c'randombytes_random
  assertBool ("Random byte '" ++ (show n) ++ "' is negative") ( n >= 0 )

test_c'sodium_memcmp :: Assertion
test_c'sodium_memcmp = do
  fPtr1 <- mallocForeignPtr :: IO (ForeignPtr CInt)
  fPtr2 <- mallocForeignPtr :: IO (ForeignPtr CInt)
  withForeignPtr fPtr1 $ \ptr1 -> withForeignPtr fPtr2 $ \ptr2 -> withCString "Hello" $ \ptr3 -> do
    poke ptr1 1; poke ptr2 2

    v1 <- peek ptr1
    let v1_size = sizeOf v1

    -- Compare two CInt of different values
    r1 <- c'sodium_memcmp (castPtr ptr1) (castPtr ptr2) (toEnum v1_size)
    r1 @?= (-1)

    -- Compare the same CInt
    r2 <- c'sodium_memcmp (castPtr ptr1) (castPtr ptr1) (toEnum v1_size)
    r2 @?= 0

    v3 <- peek ptr3
    let v3_size = sizeOf v3

    -- Compare a CInt and a CString
    r3 <- c'sodium_memcmp (castPtr ptr1) (castPtr ptr3) (toEnum v3_size)
    r3 @?= (-1)

    -- Change the value of ptr1 and compare to ptr2 again
    poke ptr1 2
    r4 <- c'sodium_memcmp (castPtr ptr1) (castPtr ptr2) (toEnum v1_size)
    r4 @?= 0
