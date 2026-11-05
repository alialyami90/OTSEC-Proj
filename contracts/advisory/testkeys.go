package advisory

// TestKeyIDs are the key IDs of every advisory test key, generated from
// advisorytest.Seeds. A release build refuses an anchor named here
// (ValidateAnchors), because the test keys' private halves are public. A
// contract test fails if this list and the seeds drift apart.
var TestKeyIDs = []string{
	"ed25519-3a9102fbf7b9c919",
	"ed25519-f4b1f22c44cbaa1a",
	"ed25519-2a843dec14a57e52",
	"ed25519-24ffe91de02b4493",
}
