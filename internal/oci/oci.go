// Package oci reads container images without a container runtime: a
// `docker save` tarball, an OCI image layout (tarball or directory), or a
// public registry over HTTPS. It never runs the image or talks to a daemon.
package oci

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
)

// Media types we understand.
const (
	mtOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mtOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mtDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtDockerManif   = "application/vnd.docker.distribution.manifest.v2+json"
	maxJSON         = 8 << 20
	DefaultPlatform = "linux/amd64"
)

// Options picks one image out of an archive, index or registry.
type Options struct {
	Platform string       // os/arch[/variant]; "" = linux/amd64 when there is a choice
	Tag      string       // for archives holding several images
	Client   *http.Client // registry client; nil = http.DefaultClient
}

// Image is one resolved image: an ordered list of layers, bottom first.
type Image struct {
	Ref       string   // what the user asked for, normalised
	Source    string   // "docker save", "OCI layout", "registry"
	Digest    string   // manifest digest when known
	Platform  string   // os/arch of the chosen manifest when known
	Others    []string // other platforms offered by the index
	Layers    []Layer
	closeFunc func() error
}

// Close releases files held open by the image.
func (im *Image) Close() error {
	if im.closeFunc != nil {
		return im.closeFunc()
	}
	return nil
}

// Layer is one filesystem layer.
type Layer struct {
	Digest    string // sha256:… of the blob as stored, "" when unknown (legacy docker save)
	MediaType string
	Size      int64
	open      func() (io.ReadCloser, error)
}

// Open returns the layer as an uncompressed tar stream. When the digest is
// known the stream fails at EOF if the blob doesn't match it.
func (l Layer) Open() (io.ReadCloser, error) {
	rc, err := l.open()
	if err != nil {
		return nil, err
	}
	var r io.Reader = rc
	if strings.HasPrefix(l.Digest, "sha256:") {
		r = &verify{r: rc, h: sha256.New(), want: strings.TrimPrefix(l.Digest, "sha256:")}
	}
	br := &peekReader{r: r}
	head, _ := br.peek(4)
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		zr, err := gzip.NewReader(br)
		if err != nil {
			rc.Close()
			return nil, fmt.Errorf("layer %s: %w", shortDigest(l.Digest), err)
		}
		return &readCloser{Reader: zr, close: rc.Close}, nil
	case len(head) == 4 && head[0] == 0x28 && head[1] == 0xb5 && head[2] == 0x2f && head[3] == 0xfd:
		rc.Close()
		return nil, fmt.Errorf("layer %s is zstd-compressed, which tickcheck can't read yet (Go's standard library has no zstd); save the image with `docker save` from an engine that stores gzip layers, or convert it: `skopeo copy --dest-compress-format gzip`", shortDigest(l.Digest))
	}
	return &readCloser{Reader: br, close: rc.Close}, nil
}

type readCloser struct {
	io.Reader
	close func() error
}

func (r *readCloser) Close() error { return r.close() }

type peekReader struct {
	r   io.Reader
	buf []byte
}

func (p *peekReader) peek(n int) ([]byte, error) {
	for len(p.buf) < n {
		b := make([]byte, n-len(p.buf))
		k, err := p.r.Read(b)
		p.buf = append(p.buf, b[:k]...)
		if err != nil {
			return p.buf, err
		}
	}
	return p.buf, nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}

type verify struct {
	r io.Reader
	h interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
	want string
}

func (v *verify) Read(b []byte) (int, error) {
	n, err := v.r.Read(b)
	v.h.Write(b[:n])
	if err == io.EOF {
		if got := hex.EncodeToString(v.h.Sum(nil)); got != v.want {
			return n, fmt.Errorf("layer sha256:%s… is corrupt: its content hashes to sha256:%s…", v.want[:12], got[:12])
		}
	}
	return n, err
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	if d == "" {
		return "(no digest)"
	}
	return "sha256:" + d + "…"
}

// LooksLikeFile reports whether arg should be treated as a path, not a registry ref.
func LooksLikeFile(arg string) bool {
	if _, err := os.Stat(arg); err == nil {
		return true
	}
	l := strings.ToLower(arg)
	for _, s := range []string{".tar", ".tar.gz", ".tgz", ".oci"} {
		if strings.HasSuffix(l, s) {
			return true
		}
	}
	return strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "~") || strings.Contains(arg, `\`)
}

// Open resolves arg (a file, a directory or a registry reference) to one image.
func Open(arg string, o Options) (*Image, error) {
	if LooksLikeFile(arg) {
		st, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("%s: no such file or directory (for a registry image pass its reference, e.g. ghcr.io/org/app:tag)", arg)
		}
		var s store
		if st.IsDir() {
			s = dirStore(arg)
		} else {
			ts, err := openTar(arg)
			if err != nil {
				return nil, err
			}
			s = ts
		}
		im, err := fromStore(s, o)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("%s: %w", arg, err)
		}
		im.closeFunc = s.Close
		return im, nil
	}
	return fromRegistry(arg, o)
}

// ---- archives ----

type store interface {
	Get(name string) (io.ReadCloser, int64, error)
	Has(name string) bool
	Close() error
}

type dirStore string

func (d dirStore) path(n string) string { return path.Join(string(d), path.Clean("/"+n)) }
func (d dirStore) Has(n string) bool {
	st, err := os.Stat(d.path(n))
	return err == nil && !st.IsDir()
}
func (d dirStore) Get(n string) (io.ReadCloser, int64, error) {
	f, err := os.Open(d.path(n))
	if err != nil {
		return nil, 0, fmt.Errorf("%s is missing from the image", n)
	}
	st, _ := f.Stat()
	return f, st.Size(), nil
}
func (d dirStore) Close() error { return nil }

type tarEntry struct {
	off, size int64
	link      string
}

type tarStore struct {
	f   *os.File
	idx map[string]tarEntry
	tmp string
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

func openTar(p string) (*tarStore, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	ts := &tarStore{f: f, idx: map[string]tarEntry{}}
	head := make([]byte, 2)
	if n, _ := io.ReadFull(f, head); n == 2 && head[0] == 0x1f && head[1] == 0x8b {
		// `docker save | gzip`: unpack once to a temp file so blobs can be read by offset
		f.Seek(0, io.SeekStart)
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		tmp, err := os.CreateTemp("", "tickcheck-image-*.tar")
		if err != nil {
			f.Close()
			return nil, err
		}
		_, err = io.Copy(tmp, zr)
		f.Close()
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ts.f, ts.tmp = tmp, tmp.Name()
	}
	ts.f.Seek(0, io.SeekStart)
	cr := &countReader{r: ts.f}
	tr := tar.NewReader(cr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			ts.Close()
			return nil, fmt.Errorf("%s is not a tar archive (%v); expected `docker save` output or an OCI image layout", p, err)
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			ts.idx[name] = tarEntry{off: cr.n, size: h.Size}
		case tar.TypeSymlink:
			ts.idx[name] = tarEntry{link: path.Join(path.Dir(name), h.Linkname)}
		case tar.TypeLink:
			ts.idx[name] = tarEntry{link: path.Clean(h.Linkname)}
		}
	}
	return ts, nil
}

func (t *tarStore) resolve(n string) (tarEntry, bool) {
	n = path.Clean(strings.TrimPrefix(n, "./"))
	for i := 0; i < 8; i++ {
		e, ok := t.idx[n]
		if !ok {
			return e, false
		}
		if e.link == "" {
			return e, true
		}
		n = e.link
	}
	return tarEntry{}, false
}

func (t *tarStore) Has(n string) bool { _, ok := t.resolve(n); return ok }
func (t *tarStore) Get(n string) (io.ReadCloser, int64, error) {
	e, ok := t.resolve(n)
	if !ok {
		return nil, 0, fmt.Errorf("%s is missing from the archive", n)
	}
	return io.NopCloser(io.NewSectionReader(t.f, e.off, e.size)), e.size, nil
}
func (t *tarStore) Close() error {
	err := t.f.Close()
	if t.tmp != "" {
		os.Remove(t.tmp)
	}
	return err
}

func readJSON(s store, name string, v any) error {
	rc, _, err := s.Get(name)
	if err != nil {
		return err
	}
	defer rc.Close()
	if err := json.NewDecoder(io.LimitReader(rc, maxJSON)).Decode(v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

func (p *platform) String() string {
	if p == nil || p.OS == "" {
		return ""
	}
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`
}

type configJSON struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant"`
}

func blobPath(d string) string { return "blobs/" + strings.Replace(d, ":", "/", 1) }

func fromStore(s store, o Options) (*Image, error) {
	if s.Has("index.json") {
		return fromOCILayout(s, o)
	}
	if s.Has("manifest.json") {
		return fromDockerSave(s, o)
	}
	return nil, errors.New("no index.json or manifest.json: not `docker save` output or an OCI image layout (`docker export` gives a plain rootfs: unpack it and use `tickcheck --root DIR`)")
}

type saveEntry struct {
	Config   string
	RepoTags []string
	Layers   []string
}

func fromDockerSave(s store, o Options) (*Image, error) {
	var es []saveEntry
	if err := readJSON(s, "manifest.json", &es); err != nil {
		return nil, err
	}
	if len(es) == 0 {
		return nil, errors.New("manifest.json lists no images")
	}
	e := es[0]
	if len(es) > 1 || o.Tag != "" {
		var tags []string
		found := false
		for _, x := range es {
			tags = append(tags, x.RepoTags...)
			for _, t := range x.RepoTags {
				if o.Tag != "" && (t == o.Tag || strings.TrimPrefix(t, "docker.io/") == o.Tag || strings.HasSuffix(t, "/"+o.Tag)) {
					e, found = x, true
				}
			}
		}
		if !found {
			if o.Tag == "" {
				return nil, fmt.Errorf("the archive holds %d images; pick one with --tag (%s)", len(es), strings.Join(tags, ", "))
			}
			return nil, fmt.Errorf("no image tagged %s in the archive (it has: %s)", o.Tag, strings.Join(tags, ", "))
		}
	}
	im := &Image{Source: "docker save"}
	if len(e.RepoTags) > 0 {
		im.Ref = e.RepoTags[0]
	}
	var cfg configJSON
	if e.Config != "" && readJSON(s, e.Config, &cfg) == nil && cfg.OS != "" {
		im.Platform = (&platform{cfg.OS, cfg.Architecture, cfg.Variant}).String()
	}
	if o.Platform != "" && im.Platform != "" && !platformMatch(o.Platform, im.Platform) {
		return nil, fmt.Errorf("the archive's image is %s, not %s (docker save keeps one platform; save it again with --platform)", im.Platform, o.Platform)
	}
	for _, l := range e.Layers {
		name := l
		var dg string
		if strings.HasPrefix(l, "blobs/sha256/") {
			dg = "sha256:" + strings.TrimPrefix(l, "blobs/sha256/")
		}
		im.Layers = append(im.Layers, Layer{Digest: dg, open: func() (io.ReadCloser, error) {
			rc, _, err := s.Get(name)
			return rc, err
		}})
	}
	return im, nil
}

func fromOCILayout(s store, o Options) (*Image, error) {
	var idx manifest
	if err := readJSON(s, "index.json", &idx); err != nil {
		return nil, err
	}
	get := func(d descriptor) (*manifest, error) {
		var m manifest
		return &m, readJSON(s, blobPath(d.Digest), &m)
	}
	cfg := func(d descriptor) string {
		var c configJSON
		if readJSON(s, blobPath(d.Digest), &c) == nil && c.OS != "" {
			return (&platform{c.OS, c.Architecture, c.Variant}).String()
		}
		return ""
	}
	// a tag filter on the top-level index (ref.name annotations)
	tops := idx.Manifests
	ref := ""
	if len(tops) > 1 || o.Tag != "" {
		var keep []descriptor
		var names []string
		for _, d := range tops {
			n := d.Annotations["org.opencontainers.image.ref.name"]
			if n == "" {
				n = d.Annotations["io.containerd.image.name"]
			}
			if n != "" {
				names = append(names, n)
			}
			if o.Tag != "" && n != "" && (n == o.Tag || strings.HasSuffix(n, ":"+o.Tag) || strings.HasSuffix(n, "/"+o.Tag)) {
				keep = append(keep, d)
				ref = n
			}
		}
		if o.Tag != "" && len(keep) == 0 {
			return nil, fmt.Errorf("no image tagged %s in index.json (it has: %s)", o.Tag, strings.Join(names, ", "))
		}
		if len(keep) > 0 {
			tops = keep
		}
	}
	if ref == "" && len(tops) == 1 {
		ref = tops[0].Annotations["io.containerd.image.name"]
		if ref == "" {
			ref = tops[0].Annotations["org.opencontainers.image.ref.name"]
		}
	}
	d, m, plat, others, err := resolve(tops, o.Platform, get, cfg)
	if err != nil {
		return nil, err
	}
	im := &Image{Source: "OCI layout", Ref: ref, Digest: d.Digest, Platform: plat, Others: others}
	for _, l := range m.Layers {
		l := l
		im.Layers = append(im.Layers, Layer{Digest: l.Digest, MediaType: l.MediaType, Size: l.Size, open: func() (io.ReadCloser, error) {
			rc, _, err := s.Get(blobPath(l.Digest))
			return rc, err
		}})
	}
	return im, nil
}

func isIndex(mt string) bool { return mt == mtOCIIndex || mt == mtDockerList }

func isAttestation(d descriptor) bool {
	return d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" || (d.Platform != nil && d.Platform.OS == "unknown")
}

func platformMatch(want, have string) bool {
	if want == have {
		return true
	}
	// "linux/arm64" matches "linux/arm64/v8"
	return strings.HasPrefix(have, want+"/")
}

// resolve walks indexes down to one image manifest.
func resolve(ds []descriptor, want string, get func(descriptor) (*manifest, error), cfg func(descriptor) string) (descriptor, *manifest, string, []string, error) {
	type cand struct {
		d    descriptor
		m    *manifest
		plat string
	}
	var cands []cand
	var walk func(ds []descriptor, depth int) error
	walk = func(ds []descriptor, depth int) error {
		if depth > 4 {
			return errors.New("index nesting too deep")
		}
		for _, d := range ds {
			if isAttestation(d) {
				continue
			}
			m, err := get(d)
			if err != nil {
				return err
			}
			if isIndex(d.MediaType) || isIndex(m.MediaType) || (len(m.Manifests) > 0 && len(m.Layers) == 0) {
				if err := walk(m.Manifests, depth+1); err != nil {
					return err
				}
				continue
			}
			p := d.Platform.String()
			if p == "" {
				p = cfg(m.Config)
			}
			cands = append(cands, cand{d, m, p})
		}
		return nil
	}
	if err := walk(ds, 0); err != nil {
		return descriptor{}, nil, "", nil, err
	}
	if len(cands) == 0 {
		return descriptor{}, nil, "", nil, errors.New("no image manifest found")
	}
	pick := -1
	target := want
	if target == "" {
		target = DefaultPlatform
	}
	for i, c := range cands {
		if platformMatch(target, c.plat) {
			pick = i
			break
		}
	}
	var all []string
	for _, c := range cands {
		if c.plat != "" {
			all = append(all, c.plat)
		}
	}
	if pick < 0 {
		if want != "" || len(cands) > 1 {
			if want == "" {
				// no linux/amd64: take the first and say which
				pick = 0
			} else {
				return descriptor{}, nil, "", nil, fmt.Errorf("no %s image here (platforms: %s)", want, strings.Join(all, ", "))
			}
		} else {
			pick = 0
		}
	}
	var others []string
	for i, c := range cands {
		if i != pick && c.plat != "" {
			others = append(others, c.plat)
		}
	}
	sort.Strings(others)
	c := cands[pick]
	return c.d, c.m, c.plat, others, nil
}
