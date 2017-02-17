module HighLevelTests where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Test.Tasty.QuickCheck as QC
import qualified Test.QuickCheck.Monadic as QC

import Crypto.LibSodium

import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Storable
import Control.Monad
import Numeric
import qualified Data.ByteString.Char8 as BS
import Text.Printf

import TestHelpers

hlTests :: [TestTree]
hlTests =
  [ testCase "sodiumInit" test_sodium_init
  , testCase "sodiumMemcmp" test_sodium_memcmp
  , QC.testProperty "sodiumBin2Hex" prop_sodiumBin2Hex
  , QC.testProperty "sodiumHex2Bin" prop_sodiumHex2Bin
  , QC.testProperty "sodiumHex2Bin_Bin2Hex" prop_sodiumHex2Bin_Bin2Hex
  , testCase "sodiumIncrement" test_sodiumIncrement
  , testCase "sodiumAdd" test_sodiumAdd
  , testCase "sodiumCompare" test_sodiumCompare
  , testCase "sodiumIsZero" test_sodiumIsZero
  , testCase "sodiumMemZero" test_sodiumMemZero
  , testCase "sodiumMLock" test_sodiumMLock
  , testCase "sodiumAllocArray" test_sodiumAllocArray
  , testCase "sodiumMProtect" test_sodiumMProtect
  , testCase "randomBytesRandom" test_randomBytesRandom
  , testCase "randomBytesUniform" test_randomBytesUniform
  , testCase "randomBytesBuf" test_randomBytesBuf
  , testCase "randomBytesStir" test_randomBytesStir
  , QC.testProperty "cryptoSecretBoxEasy" prop_cryptoSecretBoxEasy
  ]

test_sodium_init :: Assertion
test_sodium_init = do
  r <- sodiumInit
  assertBool ("sodiumInit failed with " ++ show r)
             (r == InitSuccess || r == AlreadyInitialized)

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

prop_sodiumBin2Hex :: QC.NonNegative (QC.Large Word) -> Bool
prop_sodiumBin2Hex (QC.NonNegative (QC.Large i)) =
  let h = sodiumBin2Hex (i :: Word)
  in  isHexEqual (convertEndian h) (showHex i "")

prop_sodiumHex2Bin :: QC.NonNegative (QC.Large Word) -> Bool
prop_sodiumHex2Bin (QC.NonNegative (QC.Large i)) =
  let hexStart = padHex $ showHex i ""
      (binList,_) = sodiumHex2Bin hexStart
  in  isHexEqual (showHexCUCharList binList) hexStart

prop_sodiumHex2Bin_Bin2Hex :: QC.NonNegative (QC.Large Word) -> Bool
prop_sodiumHex2Bin_Bin2Hex (QC.NonNegative (QC.Large i)) =
  let hex = printf "%016s" $ showHex i ""
      (binList,s) = sodiumHex2Bin hex
      hexResult = sodiumBin2Hex $ convertCUCharListToWord binList
  in  (s == "") && (hexResult == (convertEndian hex))

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
  withForeignPtr (unGuardedPtr gPtr) $ \ptr -> do
    pokeElemOff ptr 0 num1
    pokeElemOff ptr 1 num2

    peekElemOff ptr 0 >>= (num1 @=?)
    peekElemOff ptr 1 >>= (num2 @=?)

test_sodiumMProtect :: Assertion
test_sodiumMProtect = do
  let num = 777 :: Int
  gPtr <- sodiumMAlloc (sizeOf num)

  withForeignPtr (unGuardedPtr gPtr) $ \ptr -> do
    poke ptr num

    -- No access
    sodiumMProtectNoAccess gPtr >>= ((Right True) @=?)

    -- Readonly access
    sodiumMProtectReadonly gPtr >>= ((Right True) @=?)

    -- Read value
    peek ptr >>= (num @=?)

    -- Allow readwrite access again
    sodiumMProtectReadWrite gPtr >>= ((Right True) @=?)

    -- Write value
    poke ptr (num + 1)

    -- Read value
    peek ptr >>= ((num + 1) @=?)

test_randomBytesRandom :: Assertion
test_randomBytesRandom = replicateM_ 1000 $ do
  n <- randomBytesRandom
  assertBool ("randomBytesRandom '" ++ show n ++ "' is negative")
             (n >= 0)

test_randomBytesUniform :: Assertion
test_randomBytesUniform = replicateM_ 1000 $ do
  let bound = 10000
  n <- randomBytesUniform bound
  assertBool ("randomBytesUniform '" ++ show n ++ "' is negative")
             (n >= 0)
  assertBool ("randomBytesUniform '" ++ show n
              ++ "' is greater than " ++ show bound)
             (n <= bound)

test_randomBytesBuf :: Assertion
test_randomBytesBuf = replicateM_ 1000 $ do
  fPtr <- mallocForeignPtr :: IO (ForeignPtr Int)
  withForeignPtr fPtr $ \ptr -> do
    randomBytesBuf ptr
    n <- peek ptr
    -- Rairly will the random Int be 0
    assertBool ("randomBytesBuf '" ++ show n ++ "' is 0")
               (n /= 0)

test_randomBytesStir :: Assertion
test_randomBytesStir = do
  -- Close random resources
  randomBytesClose >>= ((Right True) @=?)

  -- Open random resources
  randomBytesStir

  -- Make sure random still works
  test_randomBytesRandom
  test_randomBytesUniform

prop_cryptoSecretBoxEasy :: String -> QC.Property
prop_cryptoSecretBoxEasy message = QC.monadicIO $ do
  let m = BS.pack message
  k <- QC.run $ newSecretBoxKey
  n <- QC.run $ newSecretBoxNonce
  let (Right c) = cryptoSecretBoxEasy m n k
      (Right c') = cryptoSecretBoxEasy m n k
      eM = cryptoSecretBoxOpenEasy c n k
  QC.assert $ c == c'
  case eM of
    (Left i)   -> QC.run $ assertFailure $
                  show i ++ " returned for message '" ++ message ++ "'"
    (Right m') -> QC.assert $ m' == m
