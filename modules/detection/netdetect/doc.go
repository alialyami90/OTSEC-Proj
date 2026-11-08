// Package netdetect is the network learner and detector of Phase 4 item 4
// (P4-4-B4), as pure functions over C13 observations, the node's session
// records and a network baseline document. It is owned by D4. The design
// is docs/phase4/D4-network-baseline.md, and the records are C13
// (contracts/netobs).
//
// It holds fc-classes/1, the one function-class table (Classify), which
// the node imports to set node.function_class.
//
// It imports no network, syscall, os/exec, store or modules/ied package
// (TestImports): the node reads and writes, and this package decides.
package netdetect
