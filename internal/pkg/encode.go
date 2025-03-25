package pkg

import (
	"encoding/json"
	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/proto"
	"net/http"
)

//想把http的响应都统一结构

// Response 统一的 API 响应结构
type Response struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
	Message any    `json:"message"`
}

// RespEncoder 统一 HTTP 响应编码
func RespEncoder(w http.ResponseWriter, r *http.Request, i any) error {
	codec := encoding.GetCodec("json")
	messageMap := make(map[string]any)

	// 解析 proto.Message
	if message, ok := i.(proto.Message); ok {
		marshalMsg, err := codec.Marshal(message)
		if err != nil {
			return err
		}
		_ = codec.Unmarshal(marshalMsg, &messageMap)

		// 处理单值情况
		if len(messageMap) == 1 {
			for _, v := range messageMap {
				i = v
			}
		}
	}

	// 生成标准响应
	resp := Response{
		Code:    200,
		Reason:  "OK",
		Message: i,
	}
	if msg, ok := messageMap["message"]; ok {
		i = msg
	}
	marshal, err := codec.Marshal(i)
	if err != nil {
		return err
	}
	err = json.Unmarshal(marshal, &resp.Message)
	if err != nil {
		return err
	}
	data, err := codec.Marshal(resp)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(data)
	if err != nil {
		return err
	}
	return nil
}
