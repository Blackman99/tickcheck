package oci

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Stats describes what Extract did.
type Stats struct {
	Layers    int   `json:"layers"`
	Files     int   `json:"files_read"`
	Bytes     int64 `json:"bytes_read"`
	Whiteouts int   `json:"whiteouts"`
	Symlinks  int   `json:"symlinks_skipped"`
	Unsafe    int   `json:"unsafe_paths_skipped"`
}

// Keep decides whether a file at an image path (slash-separated, no leading
// slash) is worth writing to disk.
type Keep func(name string) bool

// Extract applies the layers in order onto dst, writing only files keep
// accepts. Whiteouts (.wh.<name>) and opaque dirs (.wh..wh..opq) from upper
// layers delete what lower layers put there, so dst ends up as the merged
// filesystem a container would see, restricted to the kept files. Symlinks
// and device files are never created, and nothing is executed.
func Extract(im *Image, dst string, keep Keep, maxFile int64) (Stats, error) {
	var st Stats
	owner := map[string]int{} // kept file -> layer that wrote it
	removeLower := func(p string, layer int, subtree bool) {
		for f, l := range owner {
			if l >= layer {
				continue
			}
			if (!subtree && f == p) || strings.HasPrefix(f, p+"/") || (subtree && p == "") {
				os.Remove(filepath.Join(dst, filepath.FromSlash(f)))
				delete(owner, f)
			}
		}
	}
	for li, l := range im.Layers {
		rc, err := l.Open()
		if err != nil {
			return st, err
		}
		tr := tar.NewReader(rc)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				rc.Close()
				return st, fmt.Errorf("layer %d (%s): %w", li+1, shortDigest(l.Digest), err)
			}
			name, ok := clean(h.Name)
			if !ok {
				st.Unsafe++
				continue
			}
			dir, base := path.Dir(name), path.Base(name)
			if dir == "." {
				dir = ""
			}
			if base == ".wh..wh..opq" {
				st.Whiteouts++
				removeLower(dir, li, true)
				continue
			}
			if strings.HasPrefix(base, ".wh.") {
				st.Whiteouts++
				removeLower(path.Join(dir, strings.TrimPrefix(base, ".wh.")), li, false)
				continue
			}
			if name == "" {
				continue
			}
			// any entry hides whatever a lower layer had at this path
			if h.Typeflag != tar.TypeDir {
				removeLower(name, li, false)
			} else if l, ok := owner[name]; ok && l < li {
				os.Remove(filepath.Join(dst, filepath.FromSlash(name)))
				delete(owner, name)
			}
			switch h.Typeflag {
			case tar.TypeReg, tar.TypeRegA, tar.TypeLink:
			case tar.TypeSymlink:
				if keep(name) {
					st.Symlinks++
				}
				continue
			default:
				continue
			}
			if !keep(name) || h.Size > maxFile {
				continue
			}
			out := filepath.Join(dst, filepath.FromSlash(name))
			if err := mkdirs(dst, path.Dir(name)); err != nil {
				continue
			}
			os.RemoveAll(out)
			var src io.Reader = tr
			if h.Typeflag == tar.TypeLink {
				ln, ok := clean(h.Linkname)
				if !ok {
					st.Unsafe++
					continue
				}
				f, err := os.Open(filepath.Join(dst, filepath.FromSlash(ln)))
				if err != nil {
					continue // hard link to a file we didn't keep
				}
				src = f
			}
			f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				continue
			}
			n, err := io.Copy(f, io.LimitReader(src, maxFile))
			f.Close()
			if c, ok := src.(io.Closer); ok {
				c.Close()
			}
			if err != nil {
				rc.Close()
				return st, fmt.Errorf("layer %d (%s): %w", li+1, shortDigest(l.Digest), err)
			}
			if !h.ModTime.IsZero() {
				os.Chtimes(out, h.ModTime, h.ModTime)
			}
			owner[name] = li
			st.Files++
			st.Bytes += n
		}
		// drain so the digest check runs over the whole blob
		if _, err := io.Copy(io.Discard, rc); err != nil {
			rc.Close()
			return st, err
		}
		rc.Close()
		st.Layers++
	}
	pruneEmpty(dst)
	return st, nil
}

// pruneEmpty removes directories left empty by whiteouts, so a deleted
// *.dist-info doesn't linger as an empty folder that still names a package.
func pruneEmpty(dir string) bool {
	es, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	empty := true
	for _, e := range es {
		if e.IsDir() && pruneEmpty(filepath.Join(dir, e.Name())) {
			os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		empty = false
	}
	return empty
}

// clean turns a tar entry name into a safe relative slash path.
func clean(n string) (string, bool) {
	n = strings.ReplaceAll(n, `\`, "/")
	n = path.Clean("/" + n)
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." {
			return "", false
		}
	}
	n = strings.TrimPrefix(n, "/")
	if n == "." {
		n = ""
	}
	if strings.Contains(n, ":") && filepath.Separator == '\\' {
		return "", false // can't be written on Windows
	}
	return n, true
}

// mkdirs creates dir under dst, replacing any file in the way (an upper
// layer can turn a file into a directory).
func mkdirs(dst, dir string) error {
	cur := dst
	if dir == "." || dir == "" {
		return nil
	}
	for _, seg := range strings.Split(dir, "/") {
		cur = filepath.Join(cur, seg)
		st, err := os.Lstat(cur)
		if err == nil && st.IsDir() {
			continue
		}
		if err == nil {
			os.Remove(cur)
		}
		if err := os.Mkdir(cur, 0o755); err != nil {
			return err
		}
	}
	return nil
}
