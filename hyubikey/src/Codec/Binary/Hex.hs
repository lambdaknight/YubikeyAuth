{-# LANGUAGE ViewPatterns #-}

module Codec.Binary.Hex 
    (
        encode,
        decode,
        hexToByteString
    ) where

import Data.Bits
import Data.Word
import qualified Data.ByteString as BS

hexToMaybeInt :: Char -> Maybe Int
hexToMaybeInt '0' = Just 0
hexToMaybeInt '1' = Just 1
hexToMaybeInt '2' = Just 2
hexToMaybeInt '3' = Just 3
hexToMaybeInt '4' = Just 4
hexToMaybeInt '5' = Just 5
hexToMaybeInt '6' = Just 6
hexToMaybeInt '7' = Just 7
hexToMaybeInt '8' = Just 8
hexToMaybeInt '9' = Just 9
hexToMaybeInt 'A' = Just 10
hexToMaybeInt 'B' = Just 11
hexToMaybeInt 'C' = Just 12
hexToMaybeInt 'D' = Just 13
hexToMaybeInt 'E' = Just 14
hexToMaybeInt 'F' = Just 15
hexToMaybeInt 'a' = Just 10
hexToMaybeInt 'b' = Just 11
hexToMaybeInt 'c' = Just 12
hexToMaybeInt 'd' = Just 13
hexToMaybeInt 'e' = Just 14
hexToMaybeInt 'f' = Just 15
hexToMaybeInt _ = Nothing

intToMaybeHex :: Int -> Maybe Char
intToMaybeHex 0 = Just '0'
intToMaybeHex 1 = Just '1'
intToMaybeHex 2 = Just '2'
intToMaybeHex 3 = Just '3'
intToMaybeHex 4 = Just '4'
intToMaybeHex 5 = Just '5'
intToMaybeHex 6 = Just '6'
intToMaybeHex 7 = Just '7'
intToMaybeHex 8 = Just '8'
intToMaybeHex 9 = Just '9'
intToMaybeHex 10 = Just 'a'
intToMaybeHex 11 = Just 'b'
intToMaybeHex 12 = Just 'c'
intToMaybeHex 13 = Just 'd'
intToMaybeHex 14 = Just 'e'
intToMaybeHex 15 = Just 'f'
intToMaybeHex _ = Nothing

toHex :: Word8 -> String
toHex byte =
    let
        hi = fromIntegral (byte `shiftR` 4)
        lo = fromIntegral (byte .&. 0xf)
        Just hiHex = intToMaybeHex hi
        Just loHex = intToMaybeHex lo
    in [hiHex, loHex]

fromHex :: String -> Maybe Word8
fromHex ((hexToMaybeInt -> Just hi):(hexToMaybeInt -> Just lo):[]) = Just (fromIntegral (hi * 16 + lo))
fromHex _ = Nothing

stringToCharPairs :: String -> Maybe [String]
stringToCharPairs [] = Just []
stringToCharPairs (a:b:[]) = Just [[a,b]]
stringToCharPairs (a:b:(stringToCharPairs -> Just cs)) = Just ([a,b]:cs)
stringToCharPairs _ = Nothing

hexToByteString :: String -> Maybe BS.ByteString
hexToByteString (decode -> Just words) = Just (BS.pack words)
hexToByteString _ = Nothing

encode :: [Word8] -> String
encode = (>>= toHex)

decode :: String -> Maybe [Word8]
decode (stringToCharPairs -> Just xs) = mapM fromHex xs
decode _ = Nothing
