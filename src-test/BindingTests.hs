module BindingTests where

import Test.Tasty
import Test.Tasty.HUnit

import Bindings.LibSodium

import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.C.String
import Foreign.Storable
import Foreign.Ptr
import Data.Bits
import Data.Word
import System.Process
import System.Exit

bindingTests :: [TestTree]
bindingTests =
  [ testCase "c'sodium_init" test_c'sodium_init
  , testCase "c'sodium_memcmp" test_c'sodium_memcmp
  , testCase "c'sodium_bin2hex" test_c'sodium_bin2hex
  , testCase "c'sodium_hex2bin" test_c'sodium_hex2bin
  , testCase "hex2bin_bin2hex" test_hex2bin_bin2hex
  , testCase "c'sodium_increment" test_c'sodium_increment
  , testCase "c'sodium_add" test_c'sodium_add
  , testCase "c'sodium_compare" test_c'sodium_compare
  , testCase "c'sodium_is_zero" test_c'sodium_is_zero
  , testCase "c'sodium_memzero" test_c'sodium_memzero
  , testCase "c'sodium_mlock" test_c'sodium_mlock
  , testCase "c'sodium_allocarray" test_c'sodium_allocarray
  , testCase "c'sodium_mprotect" test_c'sodium_mprotect
  , testCase "c'sodium_allocarray_crash" $ test_c'sodium_crash "allocarray"
  , testCase "c'sodium_mprotect_noaccess_crash" $
             test_c'sodium_crash "mprotect_noaccess"
  , testCase "c'sodium_mprotect_readonly_crash" $
             test_c'sodium_crash "mprotect_readonly"
  , testCase "c'randombytes_random" test_c'randombytes_random
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

test_c'sodium_bin2hex :: Assertion
test_c'sodium_bin2hex = do
  fPtrBin <- mallocForeignPtr :: IO (ForeignPtr Word)
  fPtrHex <- mallocForeignPtr :: IO (ForeignPtr CChar)
  withForeignPtr fPtrBin $ \ptrBin -> withForeignPtr fPtrHex $ \ptrHex -> do
    poke ptrBin $ bit 6 .|. bit 7
    binSize <- peek ptrBin >>= return . sizeOf
    let hexSize = binSize * 2 + 1

    res <- c'sodium_bin2hex ptrHex (toEnum hexSize)
                            (castPtr ptrBin) (toEnum binSize)

    resValue <- peekCAString res
    hexValue <- peekCAString ptrHex

    assertEqual "Return and hex memory addresses are the same" ptrHex res
    assertEqual "Return and hex argument are not equal" resValue hexValue
    hexValue @?= "c000000000000000"

test_c'sodium_hex2bin :: Assertion
test_c'sodium_hex2bin = do
  fPtrBin <- mallocForeignPtr :: IO (ForeignPtr CUInt)
  fPtrBinLen <- mallocForeignPtr :: IO (ForeignPtr CSize)
  fPtrHexEnd <- mallocForeignPtr :: IO (ForeignPtr (Ptr CChar))
  let hexString = "1111zblah"
      hexLength = length hexString

  withForeignPtr fPtrBin $ \ptrBin ->
    withCString hexString $ \ptrHex ->
      withForeignPtr fPtrBinLen $ \ptrBinLen ->
        withForeignPtr fPtrHexEnd $ \ptrHexEnd -> do

    binSizeMax <- peek ptrBin >>= return . sizeOf

    res <- c'sodium_hex2bin (castPtr ptrBin) (toEnum binSizeMax)
                            ptrHex (toEnum hexLength) nullPtr
                            ptrBinLen ptrHexEnd

    binValue    <- peek ptrBin
    binLenValue <- peek ptrBinLen
    hexEndValue <- peek ptrHexEnd >>= peekCAString

    res @?= 0
    binValue @?= 4369
    binLenValue @?= 2
    hexEndValue @?= "zblah"

test_hex2bin_bin2hex :: Assertion
test_hex2bin_bin2hex = do
  fPtrBin <- mallocForeignPtr :: IO (ForeignPtr CUInt)
  fPtrBinLen <- mallocForeignPtr :: IO (ForeignPtr CSize)
  fPtrHexEnd <- mallocForeignPtr :: IO (ForeignPtr (Ptr CChar))
  let hexString = "11110c00"
      hexLength = length hexString

  withForeignPtr fPtrBin $ \ptrBin ->
    withCString hexString $ \ptrHex ->
      withForeignPtr fPtrBinLen $ \ptrBinLen ->
        withForeignPtr fPtrHexEnd $ \ptrHexEnd -> do

    binSizeMax <- peek ptrBin >>= return . sizeOf

    -- Convert to bin
    _ <- c'sodium_hex2bin (castPtr ptrBin) (toEnum binSizeMax)
                            ptrHex (toEnum hexLength) nullPtr
                            ptrBinLen ptrHexEnd

    -- Convert back to hex
    binSize' <- peek ptrBin >>= return . sizeOf
    let hexSize = binSize' * 2 + 1
    res <- c'sodium_bin2hex ptrHex (toEnum hexSize)
                            (castPtr ptrBin) (toEnum binSize')
    resValue <- peekCAString res

    resValue @?= hexString

test_c'sodium_increment :: Assertion
test_c'sodium_increment = do
  let bigNum = 1000000000000000000
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum $ \ptrNum -> do
    poke ptrNum bigNum
    c'sodium_increment (castPtr ptrNum) ((toEnum . sizeOf) bigNum)
    res <- peek ptrNum
    res @?= (bigNum + 1)

test_c'sodium_add :: Assertion
test_c'sodium_add = do
  let num1 = 10000000
  let num2 = 3434343
  fPtrNum1 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  fPtrNum2 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum1 $ \ptrNum1 ->
    withForeignPtr fPtrNum2 $ \ptrNum2 -> do

    poke ptrNum1 num1
    poke ptrNum2 num2
    c'sodium_add (castPtr ptrNum1) (castPtr ptrNum2) ((toEnum . sizeOf) num1)
    res <- peek ptrNum1
    res @?= (num1 + num2)

test_c'sodium_compare :: Assertion
test_c'sodium_compare = do
  let num1 = 10000000
  let num2 = 3434343
  fPtrNum1 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  fPtrNum2 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum1 $ \ptrNum1 ->
    withForeignPtr fPtrNum2 $ \ptrNum2 -> do

    poke ptrNum1 num1
    poke ptrNum2 num2

    -- Compare num1 and num2
    res <- c'sodium_compare (castPtr ptrNum1) (castPtr ptrNum2) ((toEnum . sizeOf) num1)
    res @?= 1

    -- Compare num1 and num1
    res2 <- c'sodium_compare (castPtr ptrNum1) (castPtr ptrNum1) ((toEnum . sizeOf) num1)
    res2 @?= 0

    -- Compare num2 and num1
    res3 <- c'sodium_compare (castPtr ptrNum2) (castPtr ptrNum1) ((toEnum . sizeOf) num1)
    res3 @?= (-1)

test_c'sodium_is_zero :: Assertion
test_c'sodium_is_zero = do
  let num1 = 10000000
  let num2 = 0
  fPtrNum1 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  fPtrNum2 <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum1 $ \ptrNum1 ->
    withForeignPtr fPtrNum2 $ \ptrNum2 -> do

    poke ptrNum1 num1
    poke ptrNum2 num2

    -- Is not all zero
    res <- c'sodium_is_zero (castPtr ptrNum1) ((toEnum . sizeOf) num1)
    res @?= 0

    -- Is all zero
    res2 <- c'sodium_is_zero (castPtr ptrNum2) ((toEnum . sizeOf) num1)
    res2 @?= 1

test_c'sodium_memzero :: Assertion
test_c'sodium_memzero = do
  let num = 711
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum $ \ptrNum -> do

    poke ptrNum num
    c'sodium_memzero (castPtr ptrNum) ((toEnum . sizeOf) num)

    res <- peek ptrNum
    res @?= 0

test_c'sodium_mlock :: Assertion
test_c'sodium_mlock = do
  let num = 10
  fPtrNum <- mallocForeignPtr :: IO (ForeignPtr Word64)
  withForeignPtr fPtrNum $ \ptrNum -> do

    poke ptrNum num
    res <- c'sodium_mlock (castPtr ptrNum) ((toEnum . sizeOf) num)
    res @?= 0

    res2 <- c'sodium_munlock (castPtr ptrNum) ((toEnum . sizeOf) num)
    res2 @?= 0

test_c'sodium_allocarray :: Assertion
test_c'sodium_allocarray = do
  let num1 = 123 :: Word64
      num2 = 4567:: Word64
  ptr <- c'sodium_allocarray (toEnum $ sizeOf num1) 2
  pokeElemOff (castPtr ptr) 0 num1
  pokeElemOff (castPtr ptr) 1 num2

  peekElemOff (castPtr ptr) 0 >>= (num1 @=?)
  peekElemOff (castPtr ptr) 1 >>= (num2 @=?)

  -- Free memory
  c'sodium_free (castPtr ptr)

test_c'sodium_mprotect :: Assertion
test_c'sodium_mprotect = do
  let num = 11109 :: Word64
  ptr <- c'sodium_malloc (toEnum $ sizeOf num)
  poke (castPtr ptr) num

  -- Set noaccess
  c'sodium_mprotect_noaccess (castPtr ptr) >>= (0 @=?)

  -- Allow readonly
  c'sodium_mprotect_readonly (castPtr ptr) >>= (0 @=?)

  -- readonly allows read access
  ptrPeek <- peek (castPtr ptr)
  ptrPeek @?= num

  -- Allow readwrite access again
  c'sodium_mprotect_readwrite (castPtr ptr) >>= (0 @=?)

  poke (castPtr ptr) (num + 1)
  peek (castPtr ptr) >>= ((num + 1) @=?)

  -- Free memory
  c'sodium_free (castPtr ptr)

test_c'sodium_crash :: String -> Assertion
test_c'sodium_crash s = do
  -- Run a script which tries to access memory which is off limits.
  res <- readCreateProcessWithExitCode
         (shell $ "stack runghc -- src-test/sodium_crash_tests.hs " ++ s)
         ""
  -- Verify that a crash occured.
  case res of
    (ExitFailure i, _, _) -> i @?= (-11)
    (ExitSuccess, _, _)  -> assertFailure
                             "Crash script didn't return error code"

-- Can be used to look at raw bit list for debugging
--bitList :: (Bits b) => b -> Maybe [Bool]
--bitList b =
--  let bSizeM = bitSizeMaybe b
--      createBitList :: (Bits b) => b -> Int -> [Bool]
--      createBitList b' i
--        | i < 0     = []
--        | otherwise = (testBit b' (i)):(createBitList b' (i-1))
--  in  maybe Nothing (Just <$> reverse . createBitList b) bSizeM
