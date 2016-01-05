{-# LINE 1 "src/System/PAM.chs" #-}{-# LANGUAGE ForeignFunctionInterface #-}

module System.PAM where

import Foreign
import Foreign.C
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable
import Control.Applicative

#include "security/pam_constants.h"
#include "security/pam_types.h"

#c
typedef struct {
	int pam_return;
	int last_session;
	int last_session_use;
} hyubikey_result;
#endc

{#enum define PamReturns {
	PAM_SUCCESS as PAMSuccess,
	PAM_OPEN_ERR as PAMOpenErr,
	PAM_SYMBOL_ERR as PAMSymbolErr,
	PAM_SERVICE_ERR as PAMServiceErr,
	PAM_SYSTEM_ERR as PAMSystemErr,
	PAM_BUF_ERR as PAMBufErr,
	PAM_CONV_ERR as PAMConvErr,
	PAM_PERM_DENIED as PAMPermDenied,
	PAM_MAXTRIES as PAMMaxTries,
	PAM_AUTH_ERR as PAMAuthErr,
	PAM_NEW_AUTHTOK_REQD as PAMNewAuthtokReqd,
	PAM_CRED_INSUFFICIENT as PAMCredInsufficient,
	PAM_AUTHINFO_UNAVAIL as PAMAuthinfoUnavail,
	PAM_USER_UNKNOWN as PAMUserUnknown,
	PAM_CRED_UNAVAIL as PAMCredUnavail,
	PAM_CRED_EXPIRED as PAMCredExpired,
	PAM_CRED_ERR as PAMCredErr,
	PAM_ACCT_EXPIRED as PAMAcctExpired,
	PAM_AUTHTOK_EXPIRED as PAMAuthtokExpired,
	PAM_SESSION_ERR as PAMSessionErr,
	PAM_AUTHTOK_ERR as PAMAuthtokErr,
	PAM_AUTHTOK_RECOVERY_ERR as PAMAuthtokRecoveryErr,
	PAM_AUTHTOK_LOCK_BUSY as PAMAuthtokLockBusy,
	PAM_AUTHTOK_DISABLE_AGING as PAMAuthtokDisableAging,
	PAM_NO_MODULE_DATA as PAMNoModuleData,
	PAM_IGNORE as PAMIgnore,
	PAM_ABORT as PAMAbort,
	PAM_TRY_AGAIN as PAMTryAgain,
	PAM_MODULE_UNKNOWN as PAMModuleUnknown,
	PAM_DOMAIN_UNKNOWN as PAMDomainUnknown} deriving (Show, Eq) #}

data HYubiKeyResult = HYubiKeyResult {
	pamReturn :: Int,
	lastSession :: Int,
	lastSessionUse :: Int
}

instance Storable HYubiKeyResult where
	alignment _ = alignment (undefined :: CDouble)
	sizeOf _ = {#sizeof hyubikey_result#}
	peek p =
		HYubiKeyResult <$> fmap fromIntegral ({#get hyubikey_result.pam_return #} p)
			<*> fmap fromIntegral ({#get hyubikey_result.last_session #} p)
			<*> fmap fromIntegral ({#get hyubikey_result.last_session_use #} p)
	poke p (HYubiKeyResult pam_return last_session last_session_use) = do
		{#set hyubikey_result.pam_return #} p (fromIntegral pam_return)
		{#set hyubikey_result.last_session #} p (fromIntegral last_session)
		{#set hyubikey_result.last_session_use #} p (fromIntegral last_session_use)

{#pointer *hyubikey_result as HYubiKeyResultPtr -> HYubiKeyResult #}