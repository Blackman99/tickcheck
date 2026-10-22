// Package ocitest builds image fixtures in memory for tests: layer tars,
// `docker save` archives, OCI layouts and a fake registry. No network, no docker.
package ocitest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"
)

// Entry is one tar member. Type: 0 file, 'd' dir, 's' symlink, 'h' hard link.
type Entry struct {
	Name, Body, Link string
	Type             byte
}

// File is a regular file entry.
func File(name, body string) Entry { return Entry{Name: name, Body: body} }

// Whiteout deletes name from lower layers.
func Whiteout(name string) Entry {
	i := strings.LastIndex(name, "/")
	return Entry{Name: name[:i+1] + ".wh." + name[i+1:]}
}

// Opaque hides everything lower layers put in dir.
func Opaque(dir string) Entry { return Entry{Name: strings.TrimSuffix(dir, "/") + "/.wh..wh..opq"} }

// Tar builds an uncompressed layer.
func Tar(es ...Entry) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	mt := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, e := range es {
		h := &tar.Header{Name: e.Name, Mode: 0o644, ModTime: mt}
		switch e.Type {
		case 'd':
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		case 's':
			h.Typeflag, h.Linkname = tar.TypeSymlink, e.Link
		case 'h':
			h.Typeflag, h.Linkname = tar.TypeLink, e.Link
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e.Body))
		}
		tw.WriteHeader(h)
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.Body))
		}
	}
	tw.Close()
	return b.Bytes()
}

// Gzip compresses b.
func Gzip(b []byte) []byte {
	var o bytes.Buffer
	zw := gzip.NewWriter(&o)
	zw.Write(b)
	zw.Close()
	return o.Bytes()
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Image is a set of layer blobs (as stored: gzip or plain) for one platform.
type Image struct {
	Platform string // os/arch
	Layers   [][]byte
}

type desc struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int               `json:"size"`
	Platform    map[string]string `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Blobs is a content-addressed blob store plus the top-level descriptor.
type Blobs struct {
	M   map[string][]byte
	Top desc
}

func (bs *Blobs) put(b []byte) string { d := digest(b); bs.M[d] = b; return d }

func (bs *Blobs) manifest(im Image) desc {
	os_, arch, _ := strings.Cut(im.Platform, "/")
	cfg, _ := json.Marshal(map[string]any{"os": os_, "architecture": arch, "rootfs": map[string]any{"type": "layers"}})
	m := map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": desc{MediaType: "application/vnd.oci.image.config.v1+json", Digest: bs.put(cfg), Size: len(cfg)}}
	var ls []desc
	for _, l := range im.Layers {
		mt := "application/vnd.oci.image.layer.v1.tar"
		if len(l) > 1 && l[0] == 0x1f {
			mt += "+gzip"
		}
		ls = append(ls, desc{MediaType: mt, Digest: bs.put(l), Size: len(l)})
	}
	m["layers"] = ls
	mb, _ := json.Marshal(m)
	return desc{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: bs.put(mb), Size: len(mb), Platform: map[string]string{"os": os_, "architecture": arch}}
}

// Build stores the images; with more than one image the top is an index.
func Build(ims ...Image) *Blobs {
	bs := &Blobs{M: map[string][]byte{}}
	if len(ims) == 1 {
		bs.Top = bs.manifest(ims[0])
		return bs
	}
	var ms []desc
	for _, im := range ims {
		ms = append(ms, bs.manifest(im))
	}
	ib, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": ms})
	bs.Top = desc{MediaType: "application/vnd.oci.image.index.v1+json", Digest: bs.put(ib), Size: len(ib)}
	return bs
}

// WriteOCI writes an OCI image layout tarball (what `docker save` writes since Docker 25, minus manifest.json).
func WriteOCI(path, refName string, bs *Blobs) error {
	top := bs.Top
	top.Annotations = map[string]string{"org.opencontainers.image.ref.name": refName}
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []desc{top}})
	es := []Entry{File("oci-layout", `{"imageLayoutVersion":"1.0.0"}`), File("index.json", string(idx))}
	for d, b := range bs.M {
		es = append(es, File("blobs/sha256/"+strings.TrimPrefix(d, "sha256:"), string(b)))
	}
	return os.WriteFile(path, Tar(es...), 0o644)
}

// WriteDockerSave writes the classic `docker save` layout: manifest.json and <id>/layer.tar.
func WriteDockerSave(path string, tags []string, layers ...[]byte) error {
	cfg := []byte(`{"os":"linux","architecture":"amd64"}`)
	var es []Entry
	var names []string
	for i, l := range layers {
		n := fmt.Sprintf("%064x/layer.tar", i+1)
		names = append(names, n)
		es = append(es, File(n, string(l)))
	}
	cname := strings.TrimPrefix(digest(cfg), "sha256:") + ".json"
	es = append(es, File(cname, string(cfg)))
	mj, _ := json.Marshal([]map[string]any{{"Config": cname, "RepoTags": tags, "Layers": names}})
	es = append(es, File("manifest.json", string(mj)))
	return os.WriteFile(path, Tar(es...), 0o644)
}

// Registry serves bs as repo:tag with the Docker token flow.
func Registry(repo, tag string, bs *Blobs) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]string{"token": "t0k"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test",scope="repository:%s:pull"`, srv.URL, repo))
			w.WriteHeader(401)
			return
		}
		pre := "/v2/" + repo + "/"
		if !strings.HasPrefix(r.URL.Path, pre) {
			w.WriteHeader(404)
			return
		}
		kind, ref, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, pre), "/")
		if kind == "manifests" && ref == tag {
			ref = bs.Top.Digest
		}
		b, ok := bs.M[ref]
		if !ok {
			w.WriteHeader(404)
			return
		}
		if kind == "manifests" {
			var m struct{ MediaType string }
			json.Unmarshal(b, &m)
			w.Header().Set("Content-Type", m.MediaType)
			w.Header().Set("Docker-Content-Digest", ref)
		}
		w.Write(b)
	}))
	return srv
}
