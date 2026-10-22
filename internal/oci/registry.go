package oci

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Ref is a parsed image reference.
type Ref struct {
	Host, Repo, Tag, Digest string
}

func (r Ref) String() string {
	s := r.Host + "/" + r.Repo
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

func (r Ref) ref() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

var refRE = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

// ParseRef parses docker-style references: python:3.12, ghcr.io/org/app@sha256:…
func ParseRef(s string) (Ref, error) {
	var r Ref
	rest := s
	if i := strings.Index(rest, "@"); i >= 0 {
		r.Digest, rest = rest[i+1:], rest[:i]
		if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(r.Digest) {
			return r, fmt.Errorf("%q: digest must be sha256:<64 hex>", s)
		}
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
		r.Tag, rest = rest[i+1:], rest[:i]
	}
	if i := strings.Index(rest, "/"); i >= 0 && (strings.ContainsAny(rest[:i], ".:") || rest[:i] == "localhost") {
		r.Host, rest = rest[:i], rest[i+1:]
	}
	if r.Host == "" {
		r.Host = "docker.io"
	}
	if r.Host == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	if !refRE.MatchString(rest) {
		return r, fmt.Errorf("%q is neither a file nor an image reference", s)
	}
	r.Repo = rest
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

type registry struct {
	c     *http.Client
	base  string
	repo  string
	mu    sync.Mutex
	token string
}

func (rg *registry) do(u, accept string) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, _ := http.NewRequest("GET", u, nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		rg.mu.Lock()
		if rg.token != "" {
			req.Header.Set("Authorization", "Bearer "+rg.token)
		}
		rg.mu.Unlock()
		resp, err := rg.c.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			ch := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			if err := rg.auth(ch); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
				return nil, errPrivate{resp.StatusCode}
			}
			return nil, fmt.Errorf("registry said %s for %s", resp.Status, u)
		}
		return resp, nil
	}
	return nil, errPrivate{401}
}

type errPrivate struct{ code int }

func (e errPrivate) Error() string {
	return fmt.Sprintf("registry said %d %s", e.code, http.StatusText(e.code))
}

var chRE = regexp.MustCompile(`(\w+)="([^"]*)"`)

// auth gets an anonymous bearer token (the Docker registry token flow).
func (rg *registry) auth(challenge string) error {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return errPrivate{401}
	}
	kv := map[string]string{}
	for _, m := range chRE.FindAllStringSubmatch(challenge, -1) {
		kv[strings.ToLower(m[1])] = m[2]
	}
	if kv["realm"] == "" {
		return errors.New("registry asked for a token without a realm")
	}
	q := url.Values{}
	if kv["service"] != "" {
		q.Set("service", kv["service"])
	}
	scope := kv["scope"]
	if scope == "" {
		scope = "repository:" + rg.repo + ":pull"
	}
	q.Set("scope", scope)
	resp, err := rg.c.Get(kv["realm"] + "?" + q.Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errPrivate{resp.StatusCode}
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSON)).Decode(&t); err != nil {
		return err
	}
	rg.mu.Lock()
	rg.token = t.Token
	if rg.token == "" {
		rg.token = t.AccessToken
	}
	rg.mu.Unlock()
	return nil
}

const acceptManifests = mtOCIIndex + ", " + mtOCIManifest + ", " + mtDockerList + ", " + mtDockerManif

func (rg *registry) manifest(ref string) (*manifest, string, error) {
	resp, err := rg.do(rg.base+"/v2/"+rg.repo+"/manifests/"+ref, acceptManifests)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var m manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSON)).Decode(&m); err != nil {
		return nil, "", fmt.Errorf("manifest %s: %w", ref, err)
	}
	if m.SchemaVersion == 1 {
		return nil, "", errors.New("this registry serves the old schema-1 manifest format, which tickcheck doesn't read; `docker pull` + `docker save` it instead")
	}
	if m.MediaType == "" {
		m.MediaType = resp.Header.Get("Content-Type")
	}
	return &m, resp.Header.Get("Docker-Content-Digest"), nil
}

func (rg *registry) blob(d string) (io.ReadCloser, error) {
	resp, err := rg.do(rg.base+"/v2/"+rg.repo+"/blobs/"+d, "")
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func fromRegistry(arg string, o Options) (*Image, error) {
	r, err := ParseRef(arg)
	if err != nil {
		return nil, err
	}
	c := o.Client
	if c == nil {
		c = http.DefaultClient
	}
	host := r.Host
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	scheme := "https"
	if h := strings.Split(host, ":")[0]; h == "localhost" || h == "127.0.0.1" || h == "::1" {
		scheme = "http" // like docker, a local registry is plain HTTP
	}
	rg := &registry{c: c, base: scheme + "://" + host, repo: r.Repo}
	wrap := func(err error) error {
		var p errPrivate
		if errors.As(err, &p) {
			return fmt.Errorf("can't pull %s anonymously (%v): it is private or doesn't exist. tickcheck only pulls public images; for a private one: docker pull %s && docker save %s -o img.tar && tickcheck image img.tar", r, p, arg, arg)
		}
		return fmt.Errorf("pulling %s: %w", r, err)
	}
	top, dg, err := rg.manifest(r.ref())
	if err != nil {
		return nil, wrap(err)
	}
	im := &Image{Source: "registry", Ref: r.String(), Digest: dg}
	var m *manifest
	if isIndex(top.MediaType) || len(top.Manifests) > 0 {
		get := func(d descriptor) (*manifest, error) {
			m, _, err := rg.manifest(d.Digest)
			return m, err
		}
		cfg := func(d descriptor) string {
			rc, err := rg.blob(d.Digest)
			if err != nil {
				return ""
			}
			defer rc.Close()
			var c configJSON
			if json.NewDecoder(io.LimitReader(rc, maxJSON)).Decode(&c) == nil && c.OS != "" {
				return (&platform{c.OS, c.Architecture, c.Variant}).String()
			}
			return ""
		}
		d, mm, plat, others, err := resolve(top.Manifests, o.Platform, get, cfg)
		if err != nil {
			return nil, wrap(err)
		}
		m, im.Digest, im.Platform, im.Others = mm, d.Digest, plat, others
	} else {
		m = top
		rc, err := rg.blob(m.Config.Digest)
		if err == nil {
			var c configJSON
			if json.NewDecoder(io.LimitReader(rc, maxJSON)).Decode(&c) == nil && c.OS != "" {
				im.Platform = (&platform{c.OS, c.Architecture, c.Variant}).String()
			}
			rc.Close()
		}
		if o.Platform != "" && im.Platform != "" && !platformMatch(o.Platform, im.Platform) {
			return nil, fmt.Errorf("%s is only published for %s", r, im.Platform)
		}
	}
	for _, l := range m.Layers {
		l := l
		im.Layers = append(im.Layers, Layer{Digest: l.Digest, MediaType: l.MediaType, Size: l.Size, open: func() (io.ReadCloser, error) {
			rc, err := rg.blob(l.Digest)
			if err != nil {
				return nil, wrap(err)
			}
			return rc, nil
		}})
	}
	return im, nil
}
