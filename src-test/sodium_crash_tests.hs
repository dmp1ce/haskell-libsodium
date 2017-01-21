{-# OPTIONS_GHC -Wall -Werror #-}

{-
The purpose of this script is the verify that accessing memory after
running various functions like 'c'sodium_mprotect_noaccess' is not allowed.
If it is tried, then the application will crash as this script proves.
-}

import Test.Tasty.HUnit
import Bindings.LibSodium
import Foreign.Ptr
import Foreign.Storable
import Data.Word
import System.Environment
import System.Exit

main :: IO ()
main = do
  _ <- c'sodium_init
  args <- getArgs
  case args of
    "mprotect_noaccess":[] -> mprotect_noaccess
    "mprotect_readonly":[] -> mprotect_readonly
    "allocarray":[] -> allocarray
    x -> die $"Unrecognized arguments: " ++ show x

allocarray :: IO ()
allocarray = do
  let num1 = 123 :: Word64
      num2 = 4567:: Word64
  ptr <- c'sodium_allocarray (toEnum $ sizeOf num1) 2
  pokeElemOff (castPtr ptr) 0 num1
  pokeElemOff (castPtr ptr) 1 num2
  -- This will crash because it is outside of array
  pokeElemOff (castPtr ptr) 2 (num2 + num1)

  peekElemOff (castPtr ptr) 0 >>= (num1 @=?)
  peekElemOff (castPtr ptr) 1 >>= (num2 @=?)

  -- Free memory
  c'sodium_free (castPtr ptr)

mprotect_noaccess :: IO ()
mprotect_noaccess = do
  let num = 109 :: Word64
  ptrNum <- c'sodium_malloc (toEnum $ sizeOf num)
  poke (castPtr ptrNum) num
    
  -- Verify that the value is stored
  numPeek <- peek (castPtr ptrNum)
  numPeek @?= (109 :: Word64)

  -- Free memory and verify it is zero afterwords
  c'sodium_mprotect_noaccess (castPtr ptrNum) >>= (0 @=?)

  numPeek2 <- peek (castPtr ptrNum)
  -- This code should crash which will be caught by the
  -- process running this script
  numPeek2 @?= (109 :: Word64)

  -- Free memory
  c'sodium_free (castPtr ptrNum)

mprotect_readonly :: IO ()
mprotect_readonly = do
  let num = 112 :: Word64
  ptrNum <- c'sodium_malloc (toEnum $ sizeOf num)
  poke (castPtr ptrNum) num
    
  -- Verify that the value is stored
  numPeek <- peek (castPtr ptrNum)
  numPeek @?= (112 :: Word64)

  -- Free memory and verify it is zero afterwords
  c'sodium_mprotect_readonly (castPtr ptrNum) >>= (0 @=?)

  -- This should work.
  numPeek2 <- peek (castPtr ptrNum)
  numPeek2 @?= (112 :: Word64)

  -- This should crash. 
  poke (castPtr ptrNum) (num + 1)

  -- Free memory
  c'sodium_free (castPtr ptrNum)
