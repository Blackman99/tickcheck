package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	t8 "github.com/Blackman99/tickcheck/internal/oci/ocitest"
)

func imageFixture(t *testing.T, layers ...[]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "img.tar")
	if err := t8.WriteOCI(p, "app:1", t8.Build(t8.Image{Platform: "linux/amd64", Layers: layers})); err != nil {
		t.Fatal(err)
	}
	return p
}

const site = "usr/local/lib/python3.12/site-packages/"

func TestImageCLI(t *testing.T) {
	bad := imageFixture(t, t8.Tar(t8.File("usr/local/lib/python3.12/os.py", "#\n"), t8.File(site+"cook.pth", "import cook\n"), t8.File(site+"cook.py", "#\n")))
	code, out, _ := runCLI(t, "image", bad, "--no-color")
	if code != exitBad || !strings.Contains(out, "the image was never run") || !strings.Contains(out, "cook.pth") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "image", "--json", bad)
	var r struct {
		Image struct{ Platform, Source string }
		Envs  []struct{ Root string }
	}
	if code != exitBad || json.Unmarshal([]byte(out), &r) != nil || r.Image.Source != "OCI layout" || r.Envs[0].Root != "/usr/local" {
		t.Fatalf("json exit %d %+v\n%s", code, r, out)
	}
	clean := imageFixture(t, t8.Tar(t8.File("etc/os-release", "x")))
	code, out, _ = runCLI(t, "image", clean, "--no-color")
	if code != exitOK || !strings.Contains(out, "No Python environments in this image") {
		t.Fatalf("clean exit %d\n%s", code, out)
	}
}

func TestImageCLIErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"image"}, exitUsage, "needs one image"},
		{[]string{"image", "a.tar", "b.tar"}, exitUsage, "needs one image"},
		{[]string{"image", "x.tar", "--root", "/tmp"}, exitUsage, "don't apply"},
		{[]string{"--platform", "linux/arm64"}, exitUsage, "only apply to `tickcheck image`"},
		{[]string{"image", "nope.tar"}, exitErr, "no such file"},
		{[]string{"app.tar"}, exitUsage, "tickcheck image app.tar"},
	} {
		code, _, errs := runCLI(t, tc.args...)
		if code != tc.code || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: exit %d %q", tc.args, code, errs)
		}
	}
}

func TestRootMustExist(t *testing.T) {
	code, _, errs := runCLI(t, "--root", "missing.tar")
	if code != exitUsage || !strings.Contains(errs, "tickcheck image missing.tar") {
		t.Fatalf("exit %d %q", code, errs)
	}
}
