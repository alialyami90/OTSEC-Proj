//go:build otsec_testclock

package node

// advisoryTestBuild is true in a build tagged otsec_testclock, the build
// C6's binaries run: the advisory test keys may be anchors, and a set
// whose purpose is test is accepted (C11 1.5 step 7 and 1.6).
const advisoryTestBuild = true
