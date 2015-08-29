#ifndef __USERS_H__
#define __USERS_H__

// Enumerations

enum UserFilterType
{
	UserFilterAll = 0,
	UserFilterNormal,
	UserFilterInterdomainTrust,
	UserFilterWorkstationTrust,
	UserFilterServerTrust,
	UserFilterTempDuplicate,
	UserFilterMax
};

enum UserType
{
	UserTypeAdministrator = 0,
	UserTypeNormal,
	UserTypeGuest
};

enum UserFlags
{
	UserFlagNone = 0x0,
	UserFlagDisabled = 0x1,
	UserFlagPasswordNotRequired = 0x2,
	UserFlagPasswordCantChange = 0x4,
	UserFlagLockedOut = 0x8,
	UserFlagPasswordCantExpire = 0x10,
	UserFlagEncryptedTextPassword = 0x20,
	UserFlagNotDelegated = 0x40,
	UserFlagSmartCardRequired = 0x80,
	UserFlagDontRequirePreAuth = 0x100,
	UserFlagTrustedForDelegation = 0x200,
	UserFlagDESKeyOnly = 0x400,
	UserFlagPasswordExpired = 0x800,
	UserFlagTrustedAuthForDelegation = 0x1000
};

inline UserFlags operator |= (UserFlags &a, UserFlags b)
{
    return a = static_cast<UserFlags>(static_cast<unsigned>(a) | static_cast<unsigned>(b));
}

enum ErrorCode // For internal error detection
{
	ErrorCodeNone,
	ErrorCodeUnknown,
	ErrorInvalidLevel,
	ErrorCodeAccessDenied,
	BufferTooSmall,
	InvalidComputer
};

// Structures

struct User
{
	unsigned long Id;
	char *Username;
	char *FullName;
	char *Description;
	UserType Type;
	UserFlags Flags;
	unsigned long GroupId;
	unsigned long PasswordAge;
	bool PasswordExpired;
	
	char *LoginServer;
	char *LoginScriptPath;
	unsigned long LoginCount;
	unsigned long FailedLoginCount;
	unsigned long LastLoginTimeStamp;
	bool Expires;
	unsigned long ExpirationTimeStamp;
};

struct ListUsersParams
{
	char *ServerName;
	UserFilterType Filter;
};

// Functions
struct User* ListUsers(struct ListUsersParams*, size_t*, ErrorCode*);
void FreeUser(struct User*);
void FreeUserArray(struct User*, size_t);

#endif