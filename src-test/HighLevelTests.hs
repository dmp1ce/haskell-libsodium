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
  , testCase "sodiumMemcmp" test_sodium_memcmp
  , testCase "sodiumBin2Hex" test_sodiumBin2Hex
  , testCase "sodiumHex2Bin" test_sodiumHex2Bin
  , testCase "sodiumHex2Bin_Bin2Hex" test_sodiumHex2Bin_Bin2Hex
  , testCase "sodiumIncrement" test_sodiumIncrement
  , testCase "sodiumAdd" test_sodiumAdd
  , testCase "sodiumCompare" test_sodiumCompare
  , testCase "sodiumIsZero" test_sodiumIsZero
  , testCase "sodiumMemZero" test_sodiumMemZero
  , testCase "sodiumMLock" test_sodiumMLock
  , testCase "sodiumAllocArray" test_sodiumAllocArray
  , testCase "sodiumMProtect" test_sodiumMProtect
  , testCase "randomInteger" test_random_integer
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
    r1 @?= Right False

    -- Compare success
    r2 <- sodiumMemcmp ptr2 ptr2
    r2 @?= Right True

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

test_sodiumAdd :: Assertion
test_sodiumAdd = do
  let num1 = 1999000001
  let num2 = 123232223
  res <- sodiumAdd num1 num2
  res @?= num1 + num2

test_sodiumCompare :: Assertion
test_sodiumCompare = do
  let num1 = 1999000001
  let num2 = 123232223
  res1 <- sodiumCompare num1 num2
  res2 <- sodiumCompare num2 num2
  res3 <- sodiumCompare num2 num1

  res1 @?= NumCompareGreaterThan
  res2 @?= NumCompareEqual
  res3 @?= NumCompareLessThan

test_sodiumIsZero :: Assertion
test_sodiumIsZero = do
  let num1 = 1001 :: Int
  res <- sodiumIsZero num1
  res @?= Right False

  res2 <- sodiumIsZero (0 :: Int)
  res2 @?= Right True

test_sodiumMemZero :: Assertion
test_sodiumMemZero = do
  let num = 711117 :: Int
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Int)
  withForeignPtr fPtrNum $ \ptrNum -> do
    poke ptrNum num
    sodiumMemZero ptrNum

    res <- peek ptrNum
    res @?= 0

test_sodiumMLock :: Assertion
test_sodiumMLock = do
  let num = 7 :: Int
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Int)
  withForeignPtr fPtrNum $ \ptrNum -> do
    poke ptrNum num
    res <- sodiumMLock ptrNum
    res @?= Right True

    res2 <- sodiumMUnlock ptrNum
    res2 @?= Right True

test_sodiumAllocArray :: Assertion
test_sodiumAllocArray = do
  let num1 = 1234 :: Int
      num2 = 5678 :: Int
  gPtr <- sodiumAllocArray (sizeOf num1) 2
  pokeElemOff (unGuardedPtr gPtr) 0 num1
  pokeElemOff (unGuardedPtr gPtr) 1 num2

  peekElemOff (unGuardedPtr gPtr) 0 >>= (num1 @=?)
  peekElemOff (unGuardedPtr gPtr) 1 >>= (num2 @=?)

  -- Free memory
  sodiumFree gPtr


test_sodiumMProtect :: Assertion
test_sodiumMProtect = do
  let num = 777 :: Int
  gPtr <- sodiumMAlloc (sizeOf num)

  poke (unGuardedPtr gPtr) num

  -- No access
  sodiumMProtectNoAccess gPtr >>= ((Right True) @=?)

  -- Readonly access
  sodiumMProtectReadonly gPtr >>= ((Right True) @=?)

  -- Read value
  peek (unGuardedPtr gPtr) >>= (num @=?)

  -- Allow readwrite access again
  sodiumMProtectReadWrite gPtr >>= ((Right True) @=?)

  -- Write value
  poke (unGuardedPtr gPtr) (num + 1)

  -- Read value
  peek (unGuardedPtr gPtr) >>= ((num + 1) @=?)

  sodiumFree gPtr
