package main

import (
	"bytes"
	"compress/gzip"
	"io"
	// "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func isCompressibleContentType(ct string) bool {
	ct = strings.ToLower(ct)
	switch {
	case strings.HasPrefix(ct, "text/"),
		strings.HasPrefix(ct, "application/json"),
		strings.HasPrefix(ct, "application/javascript"),
		strings.HasPrefix(ct, "application/xml"),
		strings.HasPrefix(ct, "application/xhtml+xml"):
		return true
	default:
		return false
	}
}

func proxy(c *gin.Context) {
	remote, err := url.Parse("http://103.20.97.127:8889") // Backend domain
	if err != nil {
		c.String(http.StatusInternalServerError, "Invalid backend URL")
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)

	// Tùy chỉnh request gửi đến backend
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = remote.Scheme
		req.URL.Host = remote.Host
		req.URL.Path = c.Param("proxyPath")
		req.URL.RawQuery = c.Request.URL.RawQuery
		req.Host = remote.Host
		req.Header = c.Request.Header.Clone()
	}

	// Tùy chỉnh response từ backend
	proxy.ModifyResponse = func(resp *http.Response) error {
		req := resp.Request
		acceptEncoding := req.Header.Get("Accept-Encoding")

		// Nếu client không hỗ trợ gzip, bỏ qua
		if !strings.Contains(acceptEncoding, "gzip") {
			return nil
		}

		// Kiểm tra có nên nén
		contentType := resp.Header.Get("Content-Type")
		if !isCompressibleContentType(contentType) {
			return nil
		}

		// Đọc toàn bộ body gốc
		// originalBody, err := io.ReadAll(resp.Body)
		// if err != nil {
		// 	return err
		// }
		// resp.Body.Close()

		// Ghi dữ liệu gzip vào buffer
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		if _, err := gzipWriter.Write([]byte("<h1>hehe</h1>")); err != nil {
			return err
		}
		gzipWriter.Close() // ⚠️ ĐÓNG ĐỂ HOÀN THÀNH NÉN

		// Gán lại body đã nén
		resp.Body = io.NopCloser(&buf)
		resp.ContentLength = int64(buf.Len()) // không cần thiết nếu chunked
		resp.Header.Set("Content-Encoding", "gzip")
		resp.Header.Del("Content-Length")
		resp.Header.Set("Content-Type", contentType)
		resp.Header.Set("Vary", "Accept-Encoding")

		return nil
	}



	proxy.ServeHTTP(c.Writer, c.Request)
}

// func main() {
// 	r := gin.Default()
// 	r.Any("/*proxyPath", proxy)
// 	log.Println("Reverse proxy running on :8080")
// 	r.Run(":8080")
// }
