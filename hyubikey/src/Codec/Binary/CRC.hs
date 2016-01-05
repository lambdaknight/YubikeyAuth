module Codec.Binary.CRC where

import Data.Word
import Data.Bits

updateCRC :: Word16 -> Word8 -> Word16
updateCRC inCRC byte =
    let
        crc' = inCRC `xor` (fromIntegral byte)
        step 8 crc = crc
        step i crc
            | crc .&. 0x1 /= 0 = step (i+1) ((shiftR crc 1) `xor` 0x8408)
            | otherwise = step (i+1) (shiftR crc 1)
    in
        step 0 crc'

calculateCRC' :: Word16 -> [Word8] -> Word16
calculateCRC' crc [] = crc
calculateCRC' crc (x:xs) = calculateCRC' (updateCRC crc x) xs

calculateCRC :: [Word8] -> Word16
calculateCRC bytes = calculateCRC' 0xffff bytes

verifyCRC' :: Word16 -> [Word8] -> Bool
verifyCRC' crc bytes = (calculateCRC' crc bytes) == 0xf0b8

verifyCRC :: [Word8] -> Bool
verifyCRC bytes = verifyCRC' 0xffff bytes