package main

// import (
// 	"bytes"
// 	"fmt"
// 	"io"
// 	"mime"
// 	"mime/multipart"
// 	"net/http"
// 	"net/http/httputil"
// 	"net/url"
// 	"strings"

// 	"github.com/gin-gonic/gin"
// )


// func getBoundary(contentType string) string {
// 	_, params, err := mime.ParseMediaType(contentType)
// 	if err != nil {
// 		return ""
// 	}
// 	return params["boundary"]
// }

// func getFilenameFromDisposition(disposition string) string {
// 	_, params, err := mime.ParseMediaType(disposition)
// 	if err != nil {
// 		return "unknown"
// 	}
// 	return params["filename"]
// }

// func proxy(c *gin.Context) {
// 	remote, err := url.Parse("http://192.168.1.13")
// 	if err != nil {
// 		panic(err)
// 	}

// 	proxy := httputil.NewSingleHostReverseProxy(remote)

// 	// Tùy chỉnh request trước khi gửi đi
// 	proxy.Director = func(req *http.Request) {
// 		req.URL.Scheme = remote.Scheme
// 		req.URL.Host = remote.Host
// 		req.URL.Path = c.Param("proxyPath")
// 		req.Host = remote.Host
// 		req.Header = c.Request.Header.Clone()

// 		var bodyBytes []byte
// 		if c.Request.Body != nil {
// 			bodyBytes, _ = io.ReadAll(c.Request.Body)
// 			c.Request.Body.Close()

// 			fmt.Println("===== Incoming Request =====")
// 			fmt.Printf("%s %s\n", c.Request.Method, c.Request.URL.Path)
// 			fmt.Println("Headers:", c.Request.Header)

// 			// Kiểm tra nếu là multipart/form-data thì phân tích file
// 			contentType := c.Request.Header.Get("Content-Type")
// 			if strings.HasPrefix(contentType, "multipart/form-data") {
// 				boundary := getBoundary(contentType)
// 				if boundary != "" {
// 					reader := multipart.NewReader(bytes.NewReader(bodyBytes), boundary)
// 					for {
// 						part, err := reader.NextPart()
// 						if err == io.EOF {
// 							break
// 						}
// 						if err != nil {
// 							fmt.Println("Lỗi đọc multipart:", err)
// 							break
// 						}

// 						disposition := part.Header.Get("Content-Disposition")
// 						if strings.Contains(disposition, "filename=") {
// 							// Đây là một file
// 							filename := getFilenameFromDisposition(disposition)
// 							fmt.Println("----- 📎 File Upload -----")
// 							fmt.Println("Tên file:", filename)
// 							fmt.Println("Content-Type:", part.Header.Get("Content-Type"))

// 							fileContent, _ := io.ReadAll(part)
// 							fmt.Println("Kích thước:", len(fileContent))
// 							// Cẩn thận in nội dung nếu là file nhị phân
// 							fmt.Println("Nội dung (text):", string(fileContent))
// 							fmt.Println("--------------------------")
// 						}
// 					}
// 				}
// 			} else {
// 				fmt.Println("Body:", string(bodyBytes))
// 			}

// 			fmt.Println("============================")
// 		}

// 		// Reset lại body
// 		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
// 		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
// 		req.ContentLength = int64(len(bodyBytes))
// 	}

// 	// Tùy chỉnh response trả về
// 	proxy.ModifyResponse = func(resp *http.Response) error {
// 		bodyBytes, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			return err
// 		}
// 		// In nội dung response
// 		// fmt.Println("===== Response from Remote =====")
// 		// fmt.Println("Status:", resp.Status)
// 		// fmt.Println("Headers:", resp.Header)
// 		// fmt.Println("Body:", string(bodyBytes))
// 		// fmt.Println("=================================")

// 		// Reset lại body cho response trước khi gửi cho client
// 		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
// 		return nil
// 	}

// 	proxy.ServeHTTP(c.Writer, c.Request)
// }

// func main() {
// 	r := gin.Default()
// 	r.Any("/*proxyPath", proxy)
// 	r.Run(":8080")
// }
