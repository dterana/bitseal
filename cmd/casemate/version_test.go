package main

import (
	"runtime/debug"
	"testing"
)

func TestBuildString(t *testing.T) {
	old := Build
	defer func() { Build = old }()
	Build = "abc1234"
	if buildString() != "abc1234" {
		t.Fatal("an explicit Build must win")
	}
	Build = "dev"
	if buildString() == "" {
		t.Fatal("buildString must never be empty")
	}
}

func TestBuildStringFrom(t *testing.T) {
	settings := func(kv ...string) *debug.BuildInfo {
		bi := &debug.BuildInfo{}
		for i := 0; i < len(kv); i += 2 {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return bi
	}
	withModule := func(v string) *debug.BuildInfo {
		bi := &debug.BuildInfo{}
		bi.Main.Version = v
		return bi
	}

	cases := []struct {
		name  string
		build string
		info  *debug.BuildInfo
		ok    bool
		want  string
	}{
		{"explicit build wins over everything", "ci-42", settings("vcs.revision", "0123456789abcdef"), true, "ci-42"},
		{"no build info", "dev", nil, false, "dev"},
		{"nil info with ok", "dev", nil, true, "dev"},
		{"long revision is shortened", "dev", settings("vcs.revision", "0123456789abcdef"), true, "0123456"},
		{"short revision kept", "dev", settings("vcs.revision", "abc"), true, "abc"},
		{"dirty tree is marked", "dev", settings("vcs.revision", "0123456789", "vcs.modified", "true"), true, "0123456-dirty"},
		{"clean tree is not marked", "dev", settings("vcs.revision", "0123456789", "vcs.modified", "false"), true, "0123456"},
		{"module version from go install", "dev", withModule("v0.3.0"), true, "v0.3.0"},
		{"development module version is ignored", "dev", withModule("(devel)"), true, "dev"},
		{"empty info", "dev", &debug.BuildInfo{}, true, "dev"},
		{"revision beats module version", "dev", func() *debug.BuildInfo {
			bi := settings("vcs.revision", "fedcba9876")
			bi.Main.Version = "v9.9.9"
			return bi
		}(), true, "fedcba9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildStringFrom(tc.build, tc.info, tc.ok); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
