package main

import "runtime/debug"

const Version = "0.3.1"

// Build is set at link time (-ldflags "-X main.Build=<rev>"); when it is not,
// buildString falls back to the VCS or module information in the binary.
var Build = "dev"

func buildString() string {
	info, ok := debug.ReadBuildInfo()
	return buildStringFrom(Build, info, ok)
}

func buildStringFrom(build string, info *debug.BuildInfo, ok bool) string {
	if build != "dev" {
		return build
	}
	if !ok || info == nil {
		return build
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
	return build
}
