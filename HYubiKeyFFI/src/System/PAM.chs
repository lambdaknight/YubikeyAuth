{-# LINE 1 "src/System/PAM.chs" #-}{-# LANGUAGE ForeignFunctionInterface #-}

module System.PAM where

import Foreign
import Foreign.C
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable
import Control.Applicative

#include <stdbool.h>
#include "security/pam_constants.h"
#include "security/pam_types.h"


#c
typedef struct {
	int success;
	int last_session;
	int last_session_use;
} hyubikey_result;
#endc

data HYubiKeyResult = HYubiKeyResult {
	success :: Bool,
	lastSession :: Int,
	lastSessionUse :: Int
}

bool2Int :: Bool -> CInt
bool2Int False = 0
bool2Int True = 1

int2Bool :: CInt -> Bool
int2Bool 0 = False
int2Bool _ = True

instance Storable HYubiKeyResult where
	alignment _ = alignment (undefined :: CDouble)
	sizeOf _ = {#sizeof hyubikey_result#}
	peek p =
		HYubiKeyResult <$> fmap int2Bool ({#get hyubikey_result.success #} p)
			<*> fmap fromIntegral ({#get hyubikey_result.last_session #} p)
			<*> fmap fromIntegral ({#get hyubikey_result.last_session_use #} p)
	poke p (HYubiKeyResult success last_session last_session_use) = do
		{#set hyubikey_result.success #} p (bool2Int success)
		{#set hyubikey_result.last_session #} p (fromIntegral last_session)
		{#set hyubikey_result.last_session_use #} p (fromIntegral last_session_use)

{#pointer *hyubikey_result as HYubiKeyResultPtr -> HYubiKeyResult #}