package main

import (
	"fmt"
	"io"
	"testing"
	// "os"
	_ "embed"
	"encoding/json"
	"io/fs"
	"net/http/httptest"
	"testing/fstest"
)

//go:embed subject.asc
var samplePkey []byte

func testFS() (fs.FS, string) {
	prefix := "terraform"
	tfs := fstest.MapFS{
		"providers/foo/bar/1.2.3": {Mode: fs.ModeDir},
		"providers/foo/bar/1.2.3/terraform-provider-bar_1.2.3_linux_amd64.zip":    {Data: []byte("zip-file")},
		"providers/foo/bar/1.2.3/terraform-provider-bar_1.2.3_SHA256SUMS":         {Data: []byte("shasum-file")},
		"providers/foo/bar/1.2.3/terraform-provider-bar_1.2.3_SHA256SUMS.sig":     {Data: []byte("gpg-signature-of-shasum-file")},
		"providers/foo/bar/1.2.3/terraform-provider-bar_1.2.3_SHA256SUMS.sig.asc": {Data: samplePkey},
	}
	return tfs, prefix
}

func TestListVersions(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/terraform/providers/v1/foo/bar/versions", nil)
	w := httptest.NewRecorder()

	tfs, pre := testFS()

	mux := NewMux(MuxParams{
		RootFS: tfs,
		Prefix: pre,
	})

	mux.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	golden := string(`{"versions":[{"version":"1.2.3","protocols":["5.2","5.1"],"platforms":[{"os":"linux","arch":"amd64"}]}]}` + "\n")

	if golden != string(body) {
		fmt.Println(string(body))
		fmt.Println(string(golden))
		t.Fatalf("Failed")
	}
}

func TestDownloadFirstVersion(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/terraform/providers/v1/foo/bar/1.2.3/download/linux/amd64", nil)
	w := httptest.NewRecorder()
	tfs, pre := testFS()

	mux := NewMux(MuxParams{
		RootFS: tfs,
		Prefix: pre,
	})
	mux.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	golden := string(`{"protocols":["5.0","5.1"],"os":"linux","arch":"amd64","filename":"terraform-provider-bar_1.2.3_linux_amd64.zip","download_url":"/terraform/downloads/blobs/providers/foo/bar/1.2.3/terraform-provider-bar_1.2.3_linux_amd64.zip","shasums_url":"/terraform/downloads/blobs/providers/foo/bar/1.2.3/terraform-provider-bar_1.2.3_SHA256SUMS","shasums_signature_url":"/terraform/downloads/blobs/providers/foo/bar/1.2.3/terraform-provider-bar_1.2.3_SHA256SUMS.sig","shasum":"4c3d59def992f6f20fafa95b008010741aa93506c83412aee2d76532261490c6","signing_keys":{"gpg_public_keys":[{"ascii_armor":"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nLoL\n-----END PGP PUBLIC KEY BLOCK-----\n"}]}}` + "\n")

	if golden != string(body) {
		fmt.Println(string(golden))
		fmt.Println(string(body))
		t.Fatalf("Failed")
	}
}

func TestDownloadBlob(t *testing.T) {
	req1 := httptest.NewRequest("GET", "http://example.com/terraform/providers/v1/foo/bar/1.2.3/download/linux/amd64", nil)
	w := httptest.NewRecorder()

	tfs, pre := testFS()
	mux := NewMux(MuxParams{
		RootFS: tfs,
		Prefix: pre,
	})
	mux.ServeHTTP(w, req1)

	resp1 := w.Result()
	dr := DownloadResponse{}
	err := json.NewDecoder(resp1.Body).Decode(&dr)
	if err != nil {
		t.Fatalf("error unmarshal")
	}

	newUrl := fmt.Sprintf("http://example.com%s", dr.DownloadURL)
	req2 := httptest.NewRequest("GET", newUrl, nil)

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req2)

	resp2 := w.Result()
	body, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("Failed: %s", err)
	}

	golden := string(`zip-file`)
	if golden != string(body) {
		fmt.Println(newUrl, string(body))
		t.Fatalf("Failed: not equal %+v", resp2)
	}
}
