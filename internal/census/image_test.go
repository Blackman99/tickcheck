package census

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/tickcheck/internal/oci"
	t8 "github.com/Blackman99/tickcheck/internal/oci/ocitest"
)

const imgSite = "usr/local/lib/python3.12/site-packages/"

// dist returns tar entries for an installed distribution with a valid RECORD.
func dist(name, ver string, files ...t8.Entry) []t8.Entry {
	di := imgSite + strings.ReplaceAll(name, "-", "_") + "-" + ver + ".dist-info/"
	var rec strings.Builder
	var out []t8.Entry
	for _, f := range files {
		h := sha256.Sum256([]byte(f.Body))
		fmt.Fprintf(&rec, "%s,sha256=%s,%d\n", f.Name, base64.RawURLEncoding.EncodeToString(h[:]), len(f.Body))
		f.Name = imgSite + f.Name
		out = append(out, f)
	}
	return append(out,
		t8.File(di+"METADATA", "Metadata-Version: 2.4\nName: "+name+"\nVersion: "+ver+"\n\n"),
		t8.File(di+"INSTALLER", "pip\n"),
		t8.File(di+"RECORD", rec.String()))
}

func baseLayer() []byte {
	es := []t8.Entry{
		t8.File("usr/local/lib/python3.12/os.py", "# os\n"),
		t8.File("usr/local/bin/python3.12", strings.Repeat("\x7fELF", 100)),
		t8.File("etc/hostname", "x\n"),
	}
	es = append(es, dist("setuptools", "80.0.0", t8.File("distutils-precedence.pth", distutilsPth), t8.File("_distutils_hack/__init__.py", "# shim\n"))...)
	return t8.Tar(es...)
}

func litellmLayer() []byte {
	cook := fmt.Sprintf(demoCookPy, strings.Repeat("QUFB", 10))
	return t8.Tar(dist("litellm", "1.107.0",
		t8.File("cook.pth", demoCookPth), t8.File("cook.py", cook),
		t8.File("sitecustomize.py", demoSiteCustom), t8.File("litellm/__init__.py", "# litellm\n"))...)
}

func scanImage(t *testing.T, arg string, io ImageOptions) *Report {
	t.Helper()
	r, err := RunImage(arg, Options{Version: "test"}, io)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hookPaths(r *Report) map[string]Verdict {
	m := map[string]Verdict{}
	for _, e := range r.Envs {
		for _, h := range e.Hooks {
			m[h.File.Path] = h.Verdict
		}
	}
	return m
}

func TestImageOCIBad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.tar")
	if err := t8.WriteOCI(p, "app:1", t8.Build(t8.Image{Platform: "linux/amd64", Layers: [][]byte{t8.Gzip(baseLayer()), t8.Gzip(litellmLayer())}})); err != nil {
		t.Fatal(err)
	}
	r := scanImage(t, p, ImageOptions{})
	if r.Worst() != Bad {
		t.Fatalf("worst %v", r.Worst())
	}
	hp := hookPaths(r)
	if hp["/"+imgSite+"cook.pth"] != Bad || hp["/"+imgSite+"distutils-precedence.pth"] != OK {
		t.Fatalf("hooks %v", hp)
	}
	if len(r.Envs) != 1 || r.Envs[0].Root != "/usr/local" || r.Envs[0].Kind != "system" || r.Envs[0].Python != "3.12" {
		t.Fatalf("env %+v", r.Envs[0])
	}
	if r.Image.Platform != "linux/amd64" || r.Image.Stats.Layers != 2 || r.Image.Source != "OCI layout" || r.Image.Ref != "app:1" {
		t.Fatalf("image %+v", r.Image)
	}
	if len(r.Exposed) != 0 || r.Home != "" {
		t.Fatal("image scan must not list this machine's credential files")
	}
	var b strings.Builder
	Render(&b, r, Style{}, false)
	out := b.String()
	for _, s := range []string{"the image was never run", "app:1 · linux/amd64", "BAD      /usr/local ", "pin litellm==1.106.2", "don't run"} {
		if !strings.Contains(out, s) {
			t.Errorf("render missing %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "tickcheck pull") || strings.Contains(out, os.TempDir()) {
		t.Errorf("render leaks pull advice or the temp dir:\n%s", out)
	}
	// the big binary was never written: nothing outside Python dirs is kept
	if r.Image.Stats.Files > 20 {
		t.Errorf("kept %d files", r.Image.Stats.Files)
	}
}

func TestImageWhiteoutsRemoveDrop(t *testing.T) {
	fix := t8.Tar(t8.Whiteout(imgSite+"cook.pth"), t8.Whiteout(imgSite+"sitecustomize.py"), t8.Whiteout(imgSite+"cook.py"),
		t8.Whiteout(imgSite+"litellm-1.107.0.dist-info"))
	p := filepath.Join(t.TempDir(), "fixed.tar")
	t8.WriteOCI(p, "app:2", t8.Build(t8.Image{Platform: "linux/amd64", Layers: [][]byte{baseLayer(), litellmLayer(), fix}}))
	r := scanImage(t, p, ImageOptions{})
	if r.Worst() != OK {
		t.Fatalf("worst %v hooks %v", r.Worst(), hookPaths(r))
	}
	if r.Image.Stats.Whiteouts != 4 {
		t.Fatalf("whiteouts %d", r.Image.Stats.Whiteouts)
	}
}

func TestImageOpaqueDir(t *testing.T) {
	// an upper layer replaces site-packages wholesale; the drop below must vanish
	up := t8.Tar(append([]t8.Entry{t8.Opaque(imgSite)}, dist("setuptools", "80.0.0", t8.File("distutils-precedence.pth", distutilsPth))...)...)
	p := filepath.Join(t.TempDir(), "o.tar")
	t8.WriteOCI(p, "app:3", t8.Build(t8.Image{Platform: "linux/amd64", Layers: [][]byte{baseLayer(), litellmLayer(), up}}))
	r := scanImage(t, p, ImageOptions{})
	if r.Worst() != OK || len(hookPaths(r)) != 1 {
		t.Fatalf("worst %v hooks %v", r.Worst(), hookPaths(r))
	}
}

func TestImageUpperLayerReAdds(t *testing.T) {
	// a whiteout in layer 2 and a fresh file in layer 3 at the same path: the file is back
	p := filepath.Join(t.TempDir(), "r.tar")
	t8.WriteOCI(p, "app:4", t8.Build(t8.Image{Platform: "linux/amd64", Layers: [][]byte{litellmLayer(), t8.Tar(t8.Whiteout(imgSite + "cook.pth")), t8.Tar(t8.File(imgSite+"cook.pth", demoCookPth))}}))
	r := scanImage(t, p, ImageOptions{})
	if hookPaths(r)["/"+imgSite+"cook.pth"] != Bad {
		t.Fatalf("hooks %v", hookPaths(r))
	}
}

func TestImageDockerSaveLegacy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "save.tar")
	if err := t8.WriteDockerSave(p, []string{"litellm/litellm:main-stable"}, baseLayer(), litellmLayer()); err != nil {
		t.Fatal(err)
	}
	r := scanImage(t, p, ImageOptions{})
	if r.Worst() != Bad || r.Image.Source != "docker save" || r.Image.Ref != "litellm/litellm:main-stable" {
		t.Fatalf("worst %v image %+v", r.Worst(), r.Image)
	}
	// gzipped archive (docker save | gzip) works too
	b, _ := os.ReadFile(p)
	gz := p + ".gz"
	os.WriteFile(gz, t8.Gzip(b), 0o644)
	if r := scanImage(t, gz, ImageOptions{}); r.Worst() != Bad {
		t.Fatal("gzipped docker save not read")
	}
}

func TestImageMultiArchIndex(t *testing.T) {
	p := filepath.Join(t.TempDir(), "multi.tar")
	clean := t8.Tar(t8.File("usr/local/lib/python3.12/os.py", "#\n"), t8.File(imgSite+"x.py", "#\n"))
	t8.WriteOCI(p, "app:5", t8.Build(
		t8.Image{Platform: "linux/arm64", Layers: [][]byte{clean}},
		t8.Image{Platform: "linux/amd64", Layers: [][]byte{litellmLayer()}}))
	r := scanImage(t, p, ImageOptions{})
	if r.Image.Platform != "linux/amd64" || r.Worst() != Bad || len(r.Image.Others) != 1 || r.Image.Others[0] != "linux/arm64" {
		t.Fatalf("default pick %+v worst %v", r.Image, r.Worst())
	}
	if r := scanImage(t, p, ImageOptions{Platform: "linux/arm64"}); r.Worst() != OK {
		t.Fatalf("arm64 worst %v", r.Worst())
	}
	_, err := RunImage(p, Options{}, ImageOptions{Platform: "windows/amd64"})
	if err == nil || !strings.Contains(err.Error(), "linux/arm64, linux/amd64") {
		t.Fatalf("err %v", err)
	}
}

func TestImageRegistry(t *testing.T) {
	bs := t8.Build(t8.Image{Platform: "linux/amd64", Layers: [][]byte{t8.Gzip(baseLayer()), t8.Gzip(litellmLayer())}},
		t8.Image{Platform: "linux/arm64", Layers: [][]byte{t8.Gzip(baseLayer())}})
	srv := t8.Registry("berriai/litellm", "main-stable", bs)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://") // 127.0.0.1:port: plain HTTP like docker
	r := scanImage(t, host+"/berriai/litellm:main-stable", ImageOptions{Client: srv.Client()})
	if r.Worst() != Bad || r.Image.Source != "registry" || !strings.HasPrefix(r.Image.Digest, "sha256:") {
		t.Fatalf("worst %v image %+v", r.Worst(), r.Image)
	}
	_, err := RunImage(host+"/berriai/nope:1", Options{}, ImageOptions{Client: srv.Client()})
	if err == nil || !strings.Contains(err.Error(), "docker save") {
		t.Fatalf("private/missing image error should point at docker save: %v", err)
	}
}

func TestImageCorruptBlob(t *testing.T) {
	dir := t.TempDir()
	bs := t8.Build(t8.Image{Platform: "linux/amd64", Layers: [][]byte{litellmLayer()}})
	for d, b := range bs.M {
		if len(b) > 2000 { // the layer
			c := append([]byte{}, b...)
			c[700] ^= 0xff
			bs.M[d] = c
		}
	}
	p := filepath.Join(dir, "bad.tar")
	t8.WriteOCI(p, "x", bs)
	_, err := RunImage(p, Options{}, ImageOptions{})
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("err %v", err)
	}
}

func TestImageUnsafePaths(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "escape")
	l := t8.Tar(t8.File("../../../../../../../../"+outside+"/x.pth", "import os\n"), t8.File(imgSite+"ok.py", "#\n"),
		t8.Entry{Name: imgSite + "link.pth", Type: 's', Link: "/etc/passwd"})
	p := filepath.Join(t.TempDir(), "u.tar")
	t8.WriteOCI(p, "x", t8.Build(t8.Image{Platform: "linux/amd64", Layers: [][]byte{l}}))
	r := scanImage(t, p, ImageOptions{})
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("tar entry escaped the extraction dir")
	}
	if r.Image.Stats.Symlinks != 1 {
		t.Fatalf("stats %+v", r.Image.Stats)
	}
}

func TestImageErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := RunImage(filepath.Join(dir, "missing.tar"), Options{}, ImageOptions{}); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("missing: %v", err)
	}
	notImg := filepath.Join(dir, "rootfs.tar")
	os.WriteFile(notImg, t8.Tar(t8.File("etc/hostname", "x")), 0o644)
	if _, err := RunImage(notImg, Options{}, ImageOptions{}); err == nil || !strings.Contains(err.Error(), "--root") {
		t.Fatalf("plain rootfs tar: %v", err)
	}
	junk := filepath.Join(dir, "junk.tar")
	os.WriteFile(junk, []byte("hello"), 0o644)
	if _, err := RunImage(junk, Options{}, ImageOptions{}); err == nil {
		t.Fatal("junk accepted")
	}
	if !oci.LooksLikeFile("img.tar") || oci.LooksLikeFile("python:3.12") {
		t.Fatal("LooksLikeFile")
	}
}

func TestKeepForCensus(t *testing.T) {
	for n, want := range map[string]bool{
		imgSite + "cook.pth":                                        true,
		imgSite + "litellm-1.107.0.dist-info/RECORD":                true,
		imgSite + "cook/__init__.py":                                true,
		imgSite + "torch/lib/libtorch_cuda.so":                      false,
		imgSite + "torch/_C.so":                                     false,
		imgSite + "__pycache__/sitecustomize.cpython-312.pyc":       true,
		"usr/lib/python3.12/sitecustomize.py":                       true,
		"usr/lib/python3.12/json/decoder.py":                        false,
		"opt/venv/pyvenv.cfg":                                       true,
		"tmp/remote_code_loader.lock":                               true,
		"root/.cache/pip/wheels/x/litellm-1.107.0-py3-none-any.whl": true,
		"usr/bin/python3":                                           false,
	} {
		if got := keepForCensus(n); got != want {
			t.Errorf("%s: got %v", n, got)
		}
	}
}

func TestParseRef(t *testing.T) {
	for in, want := range map[string]string{
		"python":                       "docker.io/library/python:latest",
		"python:3.12-slim":             "docker.io/library/python:3.12-slim",
		"ghcr.io/berriai/litellm:main": "ghcr.io/berriai/litellm:main",
		"localhost:5000/app":           "localhost:5000/app:latest",
		"org/app@sha256:" + strings.Repeat("a", 64): "docker.io/org/app@sha256:" + strings.Repeat("a", 64),
	} {
		r, err := oci.ParseRef(in)
		if err != nil || r.String() != want {
			t.Errorf("%s: %v %v", in, r, err)
		}
	}
	if _, err := oci.ParseRef("Not A Ref"); err == nil {
		t.Error("bad ref accepted")
	}
}
