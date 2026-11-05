//go:build !otsec_testclock

package node

// advisoryTestBuild is false in a release build: an advisory test key is
// refused as an anchor, and a set whose purpose is test is refused
// (C11 1.5 step 7 and 1.6). No configuration changes it.
const advisoryTestBuild = false
