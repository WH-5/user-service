package pkg

import (
	"golang.org/x/crypto/bcrypt"
	"regexp"
)

const pwdRex = "^[a-zA-Z0-9!@#$%^&*()\\-_=+.?]{8,32}$"

// PasswordIsValid 判断密码是否合法
func PasswordIsValid(pwd string) bool {
	re := regexp.MustCompile(pwdRex)
	return re.MatchString(pwd)
}

// HashPassword 加密密码
func HashPassword(pwd string) string {
	password, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
	//加密方式 使用最低成本，速度快
	if err != nil {
		panic(err)
	}
	return string(password)
}

// CheckPassword 检查密码与哈希值是否能配对
func CheckPassword(hashPwd, pwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(pwd))
	return err == nil
}
