package utils

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/basgys/goxml2json"
	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

func FlattenWithValues(data interface{}, prefix string, out map[string]interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			FlattenWithValues(val, fullKey, out)
		}
	case []interface{}:
		for i, val := range v {
			idx := strconv.Itoa(i)
			fullKey := idx
			if prefix != "" {
				fullKey = prefix + "." + idx
			}
			FlattenWithValues(val, fullKey, out)
		}
	default:
		out[prefix] = v
	}
}

func DecodeResponseBody(context *http.Response) ([]byte, error) {
	encoding := strings.ToLower(context.Header.Get("Content-Encoding"))
	var (
		reader io.ReadCloser
		err    error
	)
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(context.Body)
	case "deflate":
		reader = io.NopCloser(flate.NewReader(context.Body))
	case "zlib", "compress":
		reader, err = zlib.NewReader(context.Body)
	case "br":
		reader = io.NopCloser(brotli.NewReader(context.Body))
	case "zstd":
		zreader, zErr := zstd.NewReader(context.Body)
		if zErr != nil {
			return nil, zErr
		}
		defer zreader.Close()
		data, err := io.ReadAll(zreader)
		if err != nil {
			return nil, err
		}
		context.Body = io.NopCloser(bytes.NewReader(data))
		return data, nil
	default:
		reader = context.Body
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	context.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}

func EncodeResponseBody(respBody []byte, encoding string) ([]byte, error) {
	var (
		buf    bytes.Buffer
		writer io.WriteCloser
		err    error
	)

	switch strings.ToLower(encoding) {
	case "gzip":
		writer = gzip.NewWriter(&buf)
	case "deflate":
		writer, err = flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
	case "zlib":
		writer = zlib.NewWriter(&buf)
	case "br":
		writer = brotli.NewWriter(&buf)
	case "zstd":
		encoder, zErr := zstd.NewWriter(&buf)
		if zErr != nil {
			return nil, zErr
		}
		defer encoder.Close()
		_, err = encoder.Write(respBody)
		if err != nil {
			return nil, err
		}
		err = encoder.Close()
		return buf.Bytes(), err
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}

	// defer writer.Close()
	_, err = writer.Write(respBody)
	if err != nil {
		return nil, err
	}
	// err = writer.Close()
	// if err != nil {
	// 	return nil, err
	// }
	fmt.Println("here")

	return buf.Bytes(), nil
}

func GetResponseBodyContentType(context *http.Response) (string, any, error) {
	contentType := context.Header.Get("Content-Type")
	if len(contentType) == 0 {
		return "", nil, ToError("Content-Type not found in Response Header")
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", nil, err
	}
	formatRegex := regexp.MustCompile(`(?i)\b(json|xml|yaml|html)\b`)
	match := formatRegex.FindStringSubmatch(mediaType)
	if len(match) < 2 {
		return "", nil, ToError("")
	}
	bodyBytes, err := DecodeResponseBody(context)
	if err != nil {
		return "", nil, err
	}
	var (
		kind string
		data any
	)
	switch strings.ToLower(match[1]) {
	case "json":
		if err := json.Unmarshal(bodyBytes, &data); err != nil {
			return "", nil, err
		}
		kind = "json"
	case "xml":
		xmlReader := strings.NewReader(string(bodyBytes))
		jsonReader, err := xml2json.Convert(xmlReader)
		if err != nil {
			return "", nil, err
		} else if err := json.Unmarshal(jsonReader.Bytes(), &data); err != nil {
			return "", nil, err
		}
		kind = "xml"
	case "yaml":
		err := yaml.Unmarshal(bodyBytes, &data)
		if err != nil {
			return "", nil, err
		}
		kind = "yaml"
	case "html":
		kind = "html"
		data = string(bodyBytes)
	default:
		return "", nil, ToError("Unsupported Response Content-Type")
	}
	return kind, data, nil
}
