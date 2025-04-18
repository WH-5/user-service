// Package service  user_err.go
// Author: 王辉
// Created: 2025-03-24 23:42
// 使用时直接传入业务层返回的error即可
// 直接传服务器报错原因会有安全风险
package service

import (
	"github.com/go-kratos/kratos/v2/errors"
)

type ErrStruct struct {
	code int
	name string
}

var (
	// 特定的错误
	UserDeviceIdEmptyError        = errors.New(451, "USER_DEVICE_ID_EMPTY", "device id is empty")
	UserPhoneInvalidError         = errors.New(451, "USER_PHONE_INVALID_EMPTY", "phone number is invalid")
	UserPhoneORUniqueError        = errors.New(451, "USER_PHONE_OR_UNIQUE_EMPTY", "phone number or unique is empty")
	UserNotAccountPermissionError = errors.New(451, "USER_NO_ACCOUNT_PERMISSION", "user have no permission")
	UserProfileEmptyError         = errors.New(451, "USER_PROFILE_EMPTY", "user update profile but new profile is empty")
	// 业务逻辑返回的错误
	UserRegisterError = ErrStruct{code: 452, name: "USER_REGISTER_ERROR"}
	UserLoginError    = ErrStruct{code: 453, name: "USER_LOGIN_ERROR"}
	UserProfileError  = ErrStruct{code: 454, name: "USER_PROFILE_ERROR"}
	UserUniqueError   = ErrStruct{code: 455, name: "USER_UNIQUE_ERROR"}
	UserPasswordError = ErrStruct{code: 456, name: "USER_PASSWORD_ERROR"}
	UserInternalError = ErrStruct{code: 457, name: "USER_INTERNAL_ERROR"}
)

func UserError(e ErrStruct, err error) *errors.Error {
	return errors.New(e.code, e.name, err.Error())
}
func RegisterError(err error) *errors.Error {
	e := UserRegisterError
	return errors.New(e.code, e.name, err.Error())
}
func LoginError(err error) *errors.Error {
	e := UserLoginError
	return errors.New(e.code, e.name, err.Error())
}
func ProfileError(err error) *errors.Error {
	e := UserProfileError
	return errors.New(e.code, e.name, err.Error())
}
func UniqueError(err error) *errors.Error {
	e := UserUniqueError
	return errors.New(e.code, e.name, err.Error())
}
func PasswordError(err error) *errors.Error {
	e := UserPasswordError
	return errors.New(e.code, e.name, err.Error())
}
func InternalError(err error) *errors.Error {
	e := UserInternalError
	return errors.New(e.code, e.name, err.Error())
}
