package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Blackman99/tickcheck/internal/census"
)

// imageClient is the registry client; tests swap it.
var imageClient = &http.Client{Timeout: 15 * time.Minute}

func image(c cli, pos []string, out, errw io.Writer, st census.Style) int {
	if len(pos) != 1 {
		fmt.Fprintln(errw, "tickcheck: image needs one image: a `docker save` tarball, an OCI layout (tar or dir), or a public registry ref")
		fmt.Fprintln(errw, "  tickcheck image app.tar")
		fmt.Fprintln(errw, "  tickcheck image ghcr.io/berriai/litellm:main-stable --platform linux/arm64")
		return exitUsage
	}
	if len(c.roots) > 0 || c.home != "" || c.demo || c.noSystem {
		fmt.Fprintln(errw, "tickcheck: --root, --home, --no-system and --demo don't apply to `tickcheck image` (it scans the whole image)")
		return exitUsage
	}
	opts := census.Options{ExtraIOC: c.iocs, MaxDepth: c.maxDepth, Version: version}
	r, err := census.RunImage(pos[0], opts, census.ImageOptions{Platform: c.platform, Tag: c.tag, Client: imageClient})
	if err != nil {
		fmt.Fprintln(errw, "tickcheck:", err)
		return exitErr
	}
	if c.jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	} else {
		census.Render(out, r, st, c.all)
	}
	switch r.Worst() {
	case census.Bad:
		return exitBad
	case census.Suspect:
		return exitSuspect
	}
	return exitOK
}
