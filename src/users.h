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
	UserTypeAdministrator,
	UserTypeNormal,
	UserTypeGuest
};

// Structures

struct User
{
	unsigned long Id;
	char *Username;
	char *FullName;
	char *Description;
	UserType Type;
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
struct User* ListUsers(struct ListUsersParams*, size_t*);
void FreeUser(struct User*);
void FreeUserArray(struct User*, size_t);

#endif