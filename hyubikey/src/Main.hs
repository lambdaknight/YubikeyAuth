module Main where

import System.Environment
import System.Exit
import Codec.Crypto.YubiKeyOTP
import Data.Word
import Data.Maybe
import Data.Either.Utils
import Codec.Binary.CRC

import Numeric
import Data.Char

import Text.Format

main = do
    progName <- getProgName
    args <- getArgs

    parse args

printHex :: (Integral a, Show a) => a -> String
printHex x = showIntAtBase 16 intToDigit x ""


toHex :: (Integral a, Show a) => [a] -> String
toHex = foldl (++) "" . map printHex

instance Show YubiKeyToken where
    show (YubiKeyToken {
        deviceID = i,
        sessionCounter = s,
        timeStamp = ts,
        sessionUse = su,
        pseudoRandom = r,
        crc16 = c,
        bytes = d }) = format "YubiKeyToken { deviceID = {0}, sessionCounter = {1}, timeStamp = {2}, sessionuse = {3}, pseudoRandom = {4}, crc16 = {5}, bytes = {6}}" [toHex i, printHex s, printHex ts, printHex su,printHex r,printHex c,toHex d]

parse :: [String] -> IO ()
parse ["-h"] = usage >> exit
parse ["-t"] = do
    putStrLn (show (verifyYubiKeyToken devID 17 2 token1))
    putStrLn (show (verifyYubiKeyToken devID 17 2 token2))
    putStrLn (show (verifyYubiKeyToken devID 17 2 token3))
    putStrLn (show (verifyYubiKeyToken devID 17 2 token4))
    putStrLn (show (verifyYubiKeyToken devID 17 2 token5))
    putStrLn (show (verifyYubiKeyToken devID 17 2 token6))
    putStrLn (show (verifyYubiKeyToken devID 17 2 token7))

    putStrLn (show token1)
    putStrLn (show token2)
    putStrLn (show token3)
    putStrLn (show token4)
    putStrLn (show token5)
    putStrLn (show token6)
parse []     = usage >> exit
parse args
    | length args == 3 = putStrLn (show (checkOTP (args !! 0) (args !! 1) (args !! 2) devID 0 0))
    | otherwise = usage >> exit

usage :: IO ()
usage   = putStrLn "Usage: hyubikey [id] [key] [otp]"

exit :: IO a
exit    = exitWith ExitSuccess

die :: IO a
die     = exitWith (ExitFailure 1)

devID :: [Word8]
devID = map fromIntegral [-120,95,29,70,-27,-21]

token1 = fromRight $ getYubiKeyToken "vvheelrfrgct" "b4952d0064ac24fddb12f711d465a1a0" "vvheelrfrgctkvrcehdjnetuhevcetldcvudjtjrbggu"
token2 = fromRight $ getYubiKeyToken "vvheelrfrgct" "b4952d0064ac24fddb12f711d465a1a0" "vvheelrfrgctuvhlfflbhvjetnufciruutrtjvrrrlrh"
token3 = fromRight $ getYubiKeyToken "vvheelrfrgct" "b4952d0064ac24fddb12f711d465a1a0" "vvheelrfrgctgteengcklvvuirbccbfchbhgfuhckcgh"
token4 = fromRight $ getYubiKeyToken "vvheelrfrgct" "b4952d0064ac24fddb12f711d465a1a0" "vvheelrfrgctgvetdkvhlftletvgguvnjdhirfjnlhik"
token5 = fromRight $ getYubiKeyToken "vvheelrfrgct" "b4952d0064ac24fddb12f711d465a1a0" "vvheelrfrgctnghlrghutccgkulbfuluetcjnuffjbne"
token6 = fromRight $ getYubiKeyToken "vvheelrfrgct" "b4952d0064ac24fddb12f711d465a1a0" "vvheelrfrgctgbtrvedcgnldffrgtidlrfcrvighucde"
token7 = fromRight $ getYubiKeyToken "vvheelrfrgct" "b4952d0064ac24fddb12f711d465a1a0" "vvheelrfrgctudeegfgulbkjdrdngbrillkburvefhch"
