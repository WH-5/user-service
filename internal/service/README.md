# Service

注册
1. 手机号校验：格式（app和服务端双校验）、未注册
2. 唯一id生成 
3. 加密密码，并储存
4. 设备注册限制 每天每设备注册x个
5. 记录注册日志

登录
1. 输入唯一id或手机号
2. 验证密码
3. 生成jwt token
4. 连续失败x次，限制登录x分钟
5. 记录登录日志

修改资料
1. 输入唯一id
2. 传入要修改的字段
3. 返回修改了的字段
4. 记录日志

修改唯一id
1. 用户注册的时候，会分配一个
2. 每天只能修改一次
3. 验证修改后 合法 和有无重复的

获取用户信息

修改密码



使用 JWT（JSON Web Token） 实现注册、登录和跨微服务认证的完整流程如下：

⸻

1. 用户注册

1.1 客户端提交注册请求

用户在客户端（APP / Web）输入手机号和密码进行注册，客户端向 user-service 发送 HTTP 请求。

请求示例

POST /api/v1/register
Content-Type: application/json

{
"phone": "13500001234",
"password": "securepassword"
}



⸻

1.2 user-service 处理注册

user-service 进行以下操作：
1.	检查手机号是否已注册
2.	加密存储密码（使用 bcrypt 或 argon2）
3.	生成唯一 ID (unique_id)，用于后续身份标识
4.	存入数据库
5.	返回注册成功信息

Go 代码示例

func RegisterHandler(c *gin.Context) {
var req RegisterRequest
if err := c.ShouldBindJSON(&req); err != nil {
c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
return
}

    // 检查手机号是否已存在
    if userRepo.ExistsByPhone(req.Phone) {
        c.JSON(http.StatusConflict, gin.H{"error": "Phone already registered"})
        return
    }

    // 加密密码
    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

    // 生成唯一 ID
    uniqueID := fmt.Sprintf("user_%d", time.Now().UnixNano())

    // 存入数据库
    user := User{
        Phone:        req.Phone,
        UniqueID:     uniqueID,
        PasswordHash: string(hashedPassword),
    }
    userRepo.Create(user)

    // 返回注册成功信息
    c.JSON(http.StatusCreated, gin.H{
        "message": "Registration successful",
        "unique_id": uniqueID,
    })
}



⸻

2. 用户登录

2.1 客户端提交登录请求

用户输入手机号+密码或 unique_id+密码 进行登录，客户端向 user-service 发送请求。

请求示例

POST /api/v1/login
Content-Type: application/json

{
"unique_id": "user_12345",
"password": "securepassword"
}



⸻

2.2 user-service 处理登录
1.	查询数据库，获取用户信息
2.	校验密码
3.	检查失败次数（防止暴力破解）
4.	成功登录后，生成 JWT 令牌
5.	返回 JWT 给客户端

JWT 生成代码

func GenerateJWT(userID string) (string, error) {
secretKey := []byte("your-secret-key")

    claims := jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(24 * time.Hour).Unix(), // 24 小时后过期
        "iat":     time.Now().Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(secretKey)
}

登录处理代码

func LoginHandler(c *gin.Context) {
var req LoginRequest
if err := c.ShouldBindJSON(&req); err != nil {
c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
return
}

    // 查询用户
    user, err := userRepo.FindByUniqueID(req.UniqueID)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
        return
    }

    // 校验密码
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }

    // 生成 JWT
    token, _ := GenerateJWT(user.ID)

    // 返回 Token
    c.JSON(http.StatusOK, gin.H{
        "token":   token,
        "user_id": user.ID,
    })
}



⸻

3. 其他微服务认证

3.1 客户端请求其他微服务

用户登录成功后，客户端在每个请求的 Authorization 头中附带 Bearer <JWT>，访问 chat-service 或 message-service。

请求示例

GET /api/v1/messages
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...



⸻

3.2 chat-service 验证 JWT

chat-service 需要解析 JWT，确认用户身份。

JWT 解析代码

func ValidateJWT(tokenString string) (string, error) {
secretKey := []byte("your-secret-key")

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return secretKey, nil
    })

    if err != nil || !token.Valid {
        return "", errors.New("invalid token")
    }

    // 解析 `user_id`
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return "", errors.New("invalid token claims")
    }

    userID, ok := claims["user_id"].(string)
    if !ok {
        return "", errors.New("user_id missing in token")
    }

    return userID, nil
}



⸻

3.3 chat-service 进行身份验证

在 chat-service 的请求处理中，先解析 JWT，如果验证成功，就允许用户访问。

示例代码

func AuthMiddleware() gin.HandlerFunc {
return func(c *gin.Context) {
tokenString := c.GetHeader("Authorization")
if tokenString == "" {
c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
c.Abort()
return
}

        // 解析 Bearer 令牌
        parts := strings.Split(tokenString, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
            c.Abort()
            return
        }

        userID, err := ValidateJWT(parts[1])
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        // 将 `user_id` 存入上下文，供后续业务逻辑使用
        c.Set("user_id", userID)
        c.Next()
    }
}



⸻

4. 用户身份验证完成，微服务授权
    1.	chat-service 在 API 处理逻辑中读取 user_id：

userID, exists := c.Get("user_id")
if !exists {
c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
return
}


	2.	继续执行后续业务逻辑（如发送消息、获取聊天记录）。

⸻

总结

步骤	说明
用户注册	客户端提交手机号和密码，user-service 生成 unique_id 并存储加密密码
用户登录	user-service 验证手机号/密码，生成 JWT 并返回
客户端使用 JWT	客户端在每次请求时携带 Authorization: Bearer <JWT>
其他微服务认证	chat-service 解析 JWT，提取 user_id 并完成身份验证

✅ 这样，所有微服务都可以共享用户认证，而不需要每次都向 user-service 询问用户身份，极大提高了系统性能！ 🚀