package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"bytes"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func getPublicKey(rdr io.Reader) (string, error) {
	data, err := io.ReadAll(rdr)
	if err != nil {
		return "", fmt.Errorf("efo first")
	}

	armored := bytes.NewReader(data)
	block, err := armor.Decode(armored)
	if err != nil {
		return "", err
	}
	if block == nil || block.Type != openpgp.PublicKeyType {
		return "", fmt.Errorf("not a public key")
	}
	return string(data), nil
}

type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Version struct {
	Version   string     `json:"version"`
	Protocols []string   `json:"protocols"`
	Platforms []Platform `json:"platforms"`
}

type VersionResponse struct {
	Versions []Version `json:"versions"`
}

type GPGPublicKey struct {
	ASCIIArmor string `json:"ascii_armor"`
}

type SigningKeys struct {
	GpgPublicKeys []GPGPublicKey `json:"gpg_public_keys,omitempty"`
}

type DownloadResponse struct {
	Protocols           []string    `json:"protocols,omitempty"`
	OS                  string      `json:"os"`
	Arch                string      `json:"arch"`
	Filename            string      `json:"filename"`
	DownloadURL         string      `json:"download_url"`
	ShasumsURL          string      `json:"shasums_url"`
	ShasumsSignatureURL string      `json:"shasums_signature_url"`
	Shasum              string      `json:"shasum"`
	SigningKeys         SigningKeys `json:"signing_keys"`
}

type SDResponse struct {
	Providers string `json:"providers.v1"`
}

type MuxParams struct {
	RootFS fs.FS
	Prefix string
}

type SMux struct {
	prefix string
	rootfs fs.FS
}

func NewMux(params MuxParams) http.Handler {
	srv := http.NewServeMux()

	versionsExpr := "GET /providers/v1/{namespace}/{type}/versions"
	downloadsExpr := "GET /providers/v1/{namespace}/{type}/{version}/download/{os}/{arch}"
	blobExpr := "GET /downloads/blobs/{path...}"

	if params.Prefix != "" {
		versionsExpr = fmt.Sprintf("GET /%s/providers/v1/{namespace}/{type}/versions", params.Prefix)
		downloadsExpr = fmt.Sprintf("GET /%s/providers/v1/{namespace}/{type}/{version}/download/{os}/{arch}", params.Prefix)
		blobExpr = fmt.Sprintf("GET /%s/downloads/blobs/{path...}", params.Prefix)
	}
	mux := &SMux{
		rootfs: params.RootFS,
		prefix: params.Prefix,
	}

	srv.HandleFunc("GET /.well-known/terraform.json", mux.serviceDiscovery)
	srv.HandleFunc(versionsExpr, mux.versionsHandler)
	srv.HandleFunc(downloadsExpr, mux.downloadsHandler)
	srv.HandleFunc(blobExpr, mux.blobHandler)
	return srv
}

func main() {
	d := os.DirFS("./storage")

	log.Fatal(http.ListenAndServe(":8080", NewMux(MuxParams{
		RootFS: d,
		Prefix: "terraform",
	})))
}

func NewVersion(version string) Version {
	return Version{
		Version:   version,
		Protocols: []string{"5.2", "5.1"},
		Platforms: []Platform{
			{
				OS:   "linux",
				Arch: "amd64",
			},
		},
	}
}

func (sm *SMux) serviceDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SDResponse{
		Providers: "/" + filepath.Join(sm.prefix, "providers", "v1") + "/",
	})
}
func (sm *SMux) versionsHandler(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	ttype := r.PathValue("type")

	matches, err := fs.Glob(sm.rootfs, filepath.Join("providers", namespace, ttype, "*"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(matches) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var versions []Version
	for _, ver := range matches {
		chunks := strings.Split(ver, "/")

		versions = append(versions, NewVersion(chunks[len(chunks)-1]))
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(VersionResponse{
		Versions: versions,
	})
}

// SHA256 hashes the key
func Sha256sum(rdr io.Reader) string {
	h := sha256.New()
	io.Copy(h, rdr)
	return hex.EncodeToString(h.Sum(nil))
}

func (sm *SMux) blobHandler(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if !fs.ValidPath(path) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, err := fs.Stat(sm.rootfs, path); err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	http.ServeFileFS(w, r, sm.rootfs, path)
}

func (sm *SMux) downloadsHandler(w http.ResponseWriter, r *http.Request) {
	v := NewVersion(r.PathValue("version"))
	namespace := r.PathValue("namespace")
	ttype := r.PathValue("type")
	os := r.PathValue("os")
	arch := r.PathValue("arch")

	basefilename := fmt.Sprintf("terraform-provider-%s_%s", ttype, v.Version)
	zip_filename := fmt.Sprintf("%s_%s_%s.zip", basefilename, os, arch)
	shasum_filename := fmt.Sprintf("%s_SHA256SUMS", basefilename)
	shasum_sig_filename := fmt.Sprintf("%s_SHA256SUMS.sig", basefilename)
	shasum_sig_asc_filename := fmt.Sprintf("%s_SHA256SUMS.sig.asc", basefilename)

	zip_file_path := filepath.Join("providers", namespace, ttype, v.Version, zip_filename)
	shasum_filepath := filepath.Join("providers", namespace, ttype, v.Version, shasum_filename)
	shasum_sig_filepath := filepath.Join("providers", namespace, ttype, v.Version, shasum_sig_filename)
	shasum_sig_asc_filepath := filepath.Join("providers", namespace, ttype, v.Version, shasum_sig_asc_filename)
	f, err := sm.rootfs.Open(zip_file_path)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s", err)
		return
	}
	defer f.Close()
	checksum := Sha256sum(f)

	var pkeys []GPGPublicKey

	signingkeyFh, err := sm.rootfs.Open(shasum_sig_asc_filepath)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)

		fmt.Fprintf(w, "failed getting pgp keys %q | %v", shasum_sig_asc_filepath, err)
		return
	}

	pgpPublicKey, err := getPublicKey(signingkeyFh)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "failed gettingzzz pgp keys %q | %v", shasum_sig_asc_filepath, err)
		return
	}

	pkeys = append(pkeys, GPGPublicKey{
		ASCIIArmor: pgpPublicKey,
	})

	resp := DownloadResponse{
		Protocols:           []string{"5.0", "5.1"},
		OS:                  os,
		Arch:                arch,
		Filename:            zip_filename,
		Shasum:              checksum,
		ShasumsURL:          fmt.Sprintf("/%s/downloads/blobs/%s", sm.prefix, shasum_filepath),
		ShasumsSignatureURL: fmt.Sprintf("/%s/downloads/blobs/%s", sm.prefix, shasum_sig_filepath),
		DownloadURL:         fmt.Sprintf("/%s/downloads/blobs/%s", sm.prefix, zip_file_path),
		SigningKeys: SigningKeys{
			GpgPublicKeys: pkeys,
		},
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
