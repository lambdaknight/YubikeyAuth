{-# LANGUAGE ForeignFunctionInterface, ScopedTypeVariables #-}

module HaskellExts where

import Foreign
import Foreign.C

import System.FilePath
import System.Directory

import Control.Applicative
import Control.Monad

import Data.Char

import Text.Printf

import Text.EditDistance -- from package edit-distance ver. 0.1.2

foreign export ccall "can_find_similar_name" canFindSimilarName :: CString -> CString -> IO CInt

canFindSimilarName playerPath' playerName' = do
  playerPath <- (map toLower) <$> peekCAString playerPath'
  playerName <- (map toLower) <$> peekCAString playerName'
  elems <- filterM (\file -> doesFileExist (playerPath </> file)) =<< getDirectoryContents playerPath
  let getEditDistance = levenshteinDistance defaultEditCosts playerName
  return $ fromIntegral $ minimum (map getEditDistance elems)
