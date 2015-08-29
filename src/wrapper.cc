#include <node.h>
#include <stdlib.h>
#include <string.h>
#include "users.h"

#include <stdio.h>

void getUsers(const v8::FunctionCallbackInfo<v8::Value>&);

void init(v8::Handle<v8::Object> exports)
{
	NODE_SET_METHOD(exports, "getUsers", getUsers);
}

char* getV8String(v8::Local<v8::Value> value)
{
	char *ret = NULL;
    if (value->IsString())
	{
        v8::String::Utf8Value utf8(value);
        ret = (char*) malloc(sizeof(char) * utf8.length() + 1);
        strcpy(ret, *utf8);
    }
	return ret;
}

v8::Local<v8::Object> userStructToV8Object(v8::Isolate* isolate, struct User *user)
{
	v8::Local<v8::Object> ret = v8::Object::New(isolate);
	
	ret->Set(v8::String::NewFromUtf8(isolate, "id"), v8::Integer::New(isolate, user->Id));
	ret->Set(v8::String::NewFromUtf8(isolate, "username"), v8::String::NewFromUtf8(isolate, user->Username));
	ret->Set(v8::String::NewFromUtf8(isolate, "fullname"), v8::String::NewFromUtf8(isolate, user->FullName));
	ret->Set(v8::String::NewFromUtf8(isolate, "description"), v8::String::NewFromUtf8(isolate, user->Description));
	ret->Set(v8::String::NewFromUtf8(isolate, "type"), v8::Integer::New(isolate, user->Type));
	ret->Set(v8::String::NewFromUtf8(isolate, "flags"), v8::Integer::New(isolate, user->Flags));
	ret->Set(v8::String::NewFromUtf8(isolate, "groupId"), v8::Integer::New(isolate, user->GroupId));
	ret->Set(v8::String::NewFromUtf8(isolate, "passwordAge"), v8::Integer::New(isolate, user->PasswordAge));
	ret->Set(v8::String::NewFromUtf8(isolate, "passwordExpired"), v8::Boolean::New(isolate, user->PasswordExpired));
	ret->Set(v8::String::NewFromUtf8(isolate, "loginServer"), v8::String::NewFromUtf8(isolate, user->LoginServer));
	ret->Set(v8::String::NewFromUtf8(isolate, "loginScriptPath"), v8::String::NewFromUtf8(isolate, user->LoginScriptPath));
	ret->Set(v8::String::NewFromUtf8(isolate, "loginCount"), v8::Integer::New(isolate, user->LoginCount));
	ret->Set(v8::String::NewFromUtf8(isolate, "failedLoginCount"), v8::Integer::New(isolate, user->FailedLoginCount));
	ret->Set(v8::String::NewFromUtf8(isolate, "lastLoginTimeStamp"), v8::Integer::New(isolate, user->LastLoginTimeStamp));
	ret->Set(v8::String::NewFromUtf8(isolate, "expires"), v8::Boolean::New(isolate, user->Expires));
	ret->Set(v8::String::NewFromUtf8(isolate, "expirationTimeStamp"), v8::Integer::New(isolate, user->ExpirationTimeStamp));
	
	return ret;
}

void getUsers(const v8::FunctionCallbackInfo<v8::Value>& args)
{
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
	v8::HandleScope scope(isolate);
	
	struct ListUsersParams param = {
		NULL, UserFilterAll
	};
	
	if(args.Length() > 0 && args[0]->IsObject())
	{
		v8::Handle<v8::Object> object = v8::Handle<v8::Object>::Cast(args[0]);
		
		v8::Handle<v8::String> property = v8::String::NewFromUtf8(isolate, "server");
		if(object->Has(property))
		{
			param.ServerName = getV8String(object->Get(property));
		}
		
		property = v8::String::NewFromUtf8(isolate, "filter");
		if(object->Has(property))
		{
			v8::Handle<v8::Value> value = object->Get(property);
			if(value->IsNumber())
			{
				int64_t filter = value->IntegerValue();
				if(filter >= 0 && filter < UserFilterMax)
				{
					param.Filter = (UserFilterType)filter;
				}
			}
		}
	}
	
	size_t count = 0;
	struct User* users = ListUsers(&param, &count);
	
	v8::Handle<v8::Array> results = v8::Array::New(isolate, (int)count);
	
	if(!results.IsEmpty())
	{
		struct User* usersPtr = users;
		for(int i = 0; i < count; i++)
		{
			results->Set(i, userStructToV8Object(isolate, usersPtr++));
		}
	}
	
	args.GetReturnValue().Set(results);
	
	FreeUserArray(users, count);
	
	if(param.ServerName)
	{
		free(param.ServerName);
	}
}

NODE_MODULE(addon, init)