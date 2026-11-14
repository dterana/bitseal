package main

import "github.com/dterana/bitseal/internal/testutil"

var (
	pattern         = testutil.Pattern
	mustHex         = testutil.MustHex
	writeFile       = testutil.WriteFile
	readFile        = testutil.ReadFile
	tempLeftovers   = testutil.TempLeftovers
	noTempLeftovers = testutil.NoTempLeftovers
)
