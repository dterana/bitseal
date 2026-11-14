package main

import "runtime/debug"

const Version = "0.0.4"

// Build is set at link time (-ldflags "-X main.Build=<rev>"); when it is not,
// buildString falls back to the VCS or module information in the binary.
var Build = "dev"

func buildString() string {
	if Build != "dev" {
		return Build
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Build
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" {
		if len(rev) > 7 {
			rev = rev[:7]
		}
		if dirty {
			rev += "-dirty"
		}
		return rev
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return Build
}
