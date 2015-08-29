#include <wchar.h>
#include <stdlib.h>
#include "users.h"
#include "os.h"

#if defined(OS_WINDOWS) // Windows headers

#if !defined(UNICODE)
#define UNICODE
#endif

#pragma comment(lib, "netapi32.lib")

#include <windows.h> 
#include <lm.h>

unsigned long FilterLevelMap[UserFilterMax] = {
	0,									// UserFilterAll
	FILTER_NORMAL_ACCOUNT,				// UserFilterNormal,
	FILTER_INTERDOMAIN_TRUST_ACCOUNT,	// UserFilterInterdomainTrust
	FILTER_WORKSTATION_TRUST_ACCOUNT,	// UserFilterWorkstationTrust
	FILTER_SERVER_TRUST_ACCOUNT,		// UserFilterServerTrust
	FILTER_TEMP_DUPLICATE_ACCOUNT		// UserFilterTempDuplicate
};

#endif

#include <stdio.h>
struct User* ListUsers(struct ListUsersParams *p, size_t *c)
{
	struct User* ret = NULL;
#if defined(OS_WINDOWS)
	wchar_t *serverName = NULL;

	if(p->ServerName)
	{
		size_t serverNameLength = strlen(p->ServerName);
		serverName = (wchar_t*)malloc(sizeof(wchar_t) * serverNameLength);
		mbstowcs(serverName, p->ServerName, serverNameLength);
	}
	
	NET_API_STATUS status;
	unsigned long resumeHandle = 0, totalCount = 0;
	LPUSER_INFO_3 buffer;
	struct User* enumRet = ret;
	
	do
	{
		unsigned long count = 0, entries = 0;
		status = NetUserEnum(serverName, 3, FilterLevelMap[p->Filter], (LPBYTE*)&buffer, MAX_PREFERRED_LENGTH, &count, &entries, &resumeHandle);
		
		if(status == NERR_Success || status == ERROR_MORE_DATA)
		{
			if(buffer != NULL)
			{
				unsigned long newCount = totalCount + count;
				if(ret == NULL)
				{
					*c = count + entries;
					size_t s = sizeof(struct User) * *c;
					enumRet = ret = (struct User*)malloc(s);
					memset(ret, NULL, s);
				}
				else if(newCount > *c)
				{
					size_t newSize = sizeof(struct User) * newCount;
					size_t oldSize = sizeof(struct User) * *c;
					ret = (struct User*)realloc(ret, newSize);
					memset(ret + oldSize, NULL, newSize - oldSize);
					*c = newCount;
				}
				
				LPUSER_INFO_3 enumBuffer = buffer;
				for(;totalCount < count && enumBuffer != NULL; totalCount++, enumBuffer++, enumRet++)
				{
					enumRet->Id = enumBuffer->usri3_user_id;
					
					if(enumBuffer->usri3_name)
					{
						size_t usernameLength = wcslen(enumBuffer->usri3_name);
						enumRet->Username = (char*)malloc(sizeof(char) * ++usernameLength);
						wcstombs(enumRet->Username, enumBuffer->usri3_name, usernameLength);
					}
					
					if(enumBuffer->usri3_full_name)
					{
						size_t fullnameLength = wcslen(enumBuffer->usri3_full_name);
						enumRet->FullName = (char*)malloc(sizeof(char) * ++fullnameLength);
						wcstombs(enumRet->FullName, enumBuffer->usri3_full_name, fullnameLength);
					}
					
					if(enumBuffer->usri3_comment)
					{
						size_t descriptionLength = wcslen(enumBuffer->usri3_comment);
						enumRet->Description = (char*)malloc(sizeof(char) * ++descriptionLength);
						wcstombs(enumRet->Description, enumBuffer->usri3_comment, descriptionLength);
					}
					
					switch(enumBuffer->usri3_priv)
					{
						case USER_PRIV_ADMIN:
							enumRet->Type = UserTypeAdministrator;
							break;
						case USER_PRIV_USER:
							enumRet->Type = UserTypeNormal;
							break;
						case USER_PRIV_GUEST:
							enumRet->Type = UserTypeGuest;
							break;
					}
					
					enumRet->Flags = UserFlagNone;
					if(enumBuffer->usri3_flags & UF_ACCOUNTDISABLE)	enumRet->Flags |= UserFlagDisabled;
					if(enumBuffer->usri3_flags & UF_PASSWD_NOTREQD)	enumRet->Flags |= UserFlagPasswordNotRequired;
					if(enumBuffer->usri3_flags & UF_PASSWD_CANT_CHANGE)	enumRet->Flags |= UserFlagPasswordCantChange;
					if(enumBuffer->usri3_flags & UF_LOCKOUT)	enumRet->Flags |= UserFlagLockedOut;
					if(enumBuffer->usri3_flags & UF_DONT_EXPIRE_PASSWD)	enumRet->Flags |= UserFlagPasswordCantExpire;
					if(enumBuffer->usri3_flags & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)	enumRet->Flags |= UserFlagEncryptedTextPassword;
					if(enumBuffer->usri3_flags & UF_NOT_DELEGATED)	enumRet->Flags |= UserFlagNotDelegated;
					if(enumBuffer->usri3_flags & UF_SMARTCARD_REQUIRED)	enumRet->Flags |= UserFlagSmartCardRequired;
					if(enumBuffer->usri3_flags & UF_DONT_REQUIRE_PREAUTH)	enumRet->Flags |= UserFlagDontRequirePreAuth;
					if(enumBuffer->usri3_flags & UF_TRUSTED_FOR_DELEGATION)	enumRet->Flags |= UserFlagTrustedForDelegation;
					if(enumBuffer->usri3_flags & UF_USE_DES_KEY_ONLY)	enumRet->Flags |= UserFlagDESKeyOnly;
					if(enumBuffer->usri3_flags & UF_PASSWORD_EXPIRED)	enumRet->Flags |= UserFlagPasswordExpired;
					if(enumBuffer->usri3_flags & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)	enumRet->Flags |= UserFlagTrustedAuthForDelegation;
					
					enumRet->GroupId = enumBuffer->usri3_primary_group_id;
					enumRet->PasswordAge = enumBuffer->usri3_password_age;
					enumRet->PasswordExpired = enumBuffer->usri3_password_expired == 0;
					
					if(enumBuffer->usri3_logon_server)
					{
						size_t loginServerLength = wcslen(enumBuffer->usri3_logon_server);
						enumRet->LoginServer = (char*)malloc(sizeof(char) * ++loginServerLength);
						wcstombs(enumRet->LoginServer, enumBuffer->usri3_logon_server, loginServerLength);
					}
					
					if(enumBuffer->usri3_script_path)
					{
						size_t loginScriptPathLength = wcslen(enumBuffer->usri3_script_path);
						enumRet->LoginScriptPath = (char*)malloc(sizeof(char) * ++loginScriptPathLength);
						wcstombs(enumRet->LoginScriptPath, enumBuffer->usri3_script_path, loginScriptPathLength);
					}
					
					enumRet->LoginCount = enumBuffer->usri3_num_logons;
					enumRet->FailedLoginCount = enumBuffer->usri3_bad_pw_count;
					enumRet->LastLoginTimeStamp = enumBuffer->usri3_last_logon;
					enumRet->Expires = enumBuffer->usri3_acct_expires != TIMEQ_FOREVER;
					if(!enumRet->Expires)
					{
						enumRet->ExpirationTimeStamp = enumBuffer->usri3_acct_expires;
					}
				}
			}
		}
		else
		{
			// System error
		}
		
		if(buffer != NULL)
		{
			NetApiBufferFree(buffer);
			buffer = NULL;
			
			if(*c > totalCount) // Will need to downsize
			{
				ret = (struct User*)realloc(ret, sizeof(struct User) * totalCount);
				*c = totalCount;
			}
		}
	} while(status == ERROR_MORE_DATA);
	
	if(serverName != NULL)
	{
		free(serverName);
	}
	
#endif
	return ret;
}

void FreeUser(struct User* user)
{
	if(user->Username != NULL) free(user->Username);
	if(user->FullName != NULL) free(user->FullName);
	if(user->Description != NULL) free(user->Description);
	if(user->LoginServer != NULL) free(user->LoginServer);
	if(user->LoginScriptPath != NULL) free(user->LoginScriptPath);
}

void FreeUserArray(struct User* users, size_t length)
{
	struct User* ptr = users;
	for(size_t i = 0; i < length; i++)
	{
		FreeUser(ptr++);
	}
	
	free(users);
}