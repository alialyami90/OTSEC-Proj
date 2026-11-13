package linkkey

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"sync"
	"testing"
)

// NK-2, D6's N3 on #672, option (a). The import test shows only that no
// package but platform/sensorlink names the reader. That the signer stays
// in platform/sensorlink depends on what that package exports, and this
// test reads its exported declarations with go/types: none of them exposes
// a signer to an importer, platform/node among them. A type may hold one in
// unexported fields, so the node can keep an opaque handle and pass it back
// to the package's dialer (D5 on #672, D3's ruling).
//
// A value flows out to the importer from an exported variable, from an
// exported type, and from the results of an exported function or method.
// From there it follows exported and embedded struct fields, the elements
// of pointers, slices, arrays, maps and channels, the exported methods of
// a type and the methods of an interface, and the results of a function.
// The arguments of a function the importer passes in flow out, and so do
// the elements of a pointer, slice, map or channel it passes in, which the
// package can write. Anything else the importer passes in flows in, so the
// node may hand the package its providers (nodekey.Keys).
//
// A signer type is crypto.Signer, crypto.PrivateKey, linkkey.Key,
// tls.Certificate, tls.Config, any type, interface or concrete, that has
// crypto.Signer's methods, or a function of crypto.Signer.Sign's form, so
// that a handle's Sign method alone exposes the key.
//
// Limit: the test reads static types. A signer handed out as any, or in
// an interface without crypto.Signer's methods, is not found, and nor is
// what the package itself does with the key, a listener included; D3's
// review of the wiring is the check there.

const sensorlinkPath = "otsec.local/otsec/platform/sensorlink"

var (
	srcOnce sync.Once
	srcFset = token.NewFileSet()
	srcImp  types.ImporterFrom
)

// source type-checks packages from their source, with cgo off so that no C
// compiler is needed.
func source() types.ImporterFrom {
	srcOnce.Do(func() {
		build.Default.CgoEnabled = false
		srcImp = &cached{src: importer.ForCompiler(srcFset, "source", nil).(types.ImporterFrom), pkgs: map[string]*types.Package{}}
	})
	return srcImp
}

// cached keeps each package by its path, since the source importer runs
// the go command to find a package each time it is asked for one.
type cached struct {
	src  types.ImporterFrom
	pkgs map[string]*types.Package
}

func (c *cached) Import(path string) (*types.Package, error) { return c.ImportFrom(path, ".", 0) }

func (c *cached) ImportFrom(path, dir string, mode types.ImportMode) (*types.Package, error) {
	if p := c.pkgs[path]; p != nil {
		return p, nil
	}
	p, err := c.src.ImportFrom(path, dir, mode)
	if err == nil {
		c.pkgs[path] = p
	}
	return p, err
}

// signerNames are the signer types named by package path and name.
var signerNames = []string{
	"crypto.Signer", "crypto.PrivateKey", readerPath + ".Key",
	"crypto/tls.Certificate", "crypto/tls.Config",
}

// leaks lists each way an exported declaration of pkg hands out a signer
// type, as a path from the declaration.
func leaks(t *testing.T, pkg *types.Package) []string {
	t.Helper()
	crypto, err := source().ImportFrom("crypto", ".", 0)
	if err != nil {
		t.Fatal(err)
	}
	signer := crypto.Scope().Lookup("Signer").Type().Underlying().(*types.Interface)
	sign, _, _ := types.LookupFieldOrMethod(signer, false, nil, "Sign")
	w := &walk{signer: signer, sign: sign.Type().(*types.Signature), seen: map[seen]bool{}}
	s := pkg.Scope()
	for _, name := range s.Names() {
		switch o := s.Lookup(name); {
		case !o.Exported():
		case isA[*types.Func](o):
			w.visit(o.Type(), true, name)
		case isA[*types.Var](o):
			w.visit(o.Type(), true, name)
			w.visit(o.Type(), false, name)
		case isA[*types.TypeName](o):
			w.visit(o.Type(), true, name)
		}
	}
	return w.found
}

func isA[T types.Object](o types.Object) bool { _, ok := o.(T); return ok }

type seen struct {
	t   types.Type
	out bool
}

type walk struct {
	signer *types.Interface
	sign   *types.Signature
	seen   map[seen]bool
	found  []string
}

func (w *walk) isSigner(t types.Type) bool {
	if n, ok := t.(*types.Named); ok && n.Obj().Pkg() != nil &&
		slices.Contains(signerNames, n.Obj().Pkg().Path()+"."+n.Obj().Name()) {
		return true
	}
	if s, ok := t.(*types.Signature); ok {
		return types.Identical(s, w.sign)
	}
	if types.IsInterface(t) {
		return types.Implements(t, w.signer)
	}
	return types.Implements(t, w.signer) || types.Implements(types.NewPointer(t), w.signer)
}

// visit follows t, whose values flow out to the importer if out, and in
// from it otherwise.
func (w *walk) visit(t types.Type, out bool, at string) {
	t = types.Unalias(t)
	if w.seen[seen{t, out}] {
		return
	}
	w.seen[seen{t, out}] = true
	if out && w.isSigner(t) {
		w.found = append(w.found, at+": "+t.String())
		return
	}
	// elem follows an element the package can write in either direction.
	elem := func(e types.Type, at string) {
		w.visit(e, out, at)
		if !out {
			w.visit(e, true, at)
		}
	}
	switch t := t.(type) {
	case *types.Named:
		w.visit(t.Underlying(), out, at)
		if out {
			for _, ms := range []*types.MethodSet{types.NewMethodSet(t), types.NewMethodSet(types.NewPointer(t))} {
				for i := range ms.Len() {
					if m := ms.At(i).Obj(); m.Exported() {
						w.visit(m.Type(), true, at+"."+m.Name())
					}
				}
			}
		}
	case *types.Pointer:
		elem(t.Elem(), at)
	case *types.Slice:
		elem(t.Elem(), at+"[]")
	case *types.Chan:
		elem(t.Elem(), at+"<-")
	case *types.Map:
		elem(t.Key(), at+"[key]")
		elem(t.Elem(), at+"[]")
	case *types.Array:
		w.visit(t.Elem(), out, at+"[]")
	case *types.Struct:
		for i := range t.NumFields() {
			if f := t.Field(i); f.Exported() || f.Embedded() {
				w.visit(f.Type(), out, at+"."+f.Name())
			}
		}
	case *types.Signature:
		for v := range t.Results().Variables() {
			w.visit(v.Type(), out, at+"()")
		}
		for v := range t.Params().Variables() {
			w.visit(v.Type(), !out, at+"("+v.Name()+")")
		}
	case *types.Interface:
		for i := range t.NumMethods() {
			w.visit(t.Method(i).Type(), out, at+"."+t.Method(i).Name())
		}
	}
}

// TestSensorlinkKeepsSigner: no exported declaration of platform/sensorlink
// exposes a signer. Control: platform/sensorlink exports a function
// that returns *linkkey.Key (D6's K11 on #672).
func TestSensorlinkKeepsSigner(t *testing.T) {
	pkg, err := source().ImportFrom(sensorlinkPath, ".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(pkg.Scope().Names()); n < 10 {
		t.Fatalf("only %d declarations read in %s", n, sensorlinkPath)
	}
	for _, l := range leaks(t, pkg) {
		t.Errorf("%s exposes a signer: %s", sensorlinkPath, l)
	}
}

// TestSignerCheckBites: on packages of one declaration each, the check
// finds each way of exposing a signer, and passes what is not one. Each
// rule of walk.visit, leaks and isSigner has a case that fails without it
// (D6's N6 on #672).
func TestSignerCheckBites(t *testing.T) {
	const head = `package x

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"io"

	"otsec.local/otsec/modules/security/linkkey"
	"otsec.local/otsec/modules/security/nodekey"
)

var (
	_ crypto.Signer
	_ *ecdsa.PrivateKey
	_ *tls.Config
	_ *linkkey.Key
	_ nodekey.Keys
	_ io.Reader
)

`
	for name, c := range map[string]struct {
		src  string
		want bool
	}{
		"a *linkkey.Key result":    {`func LinkKey(path, nodeID string) (*linkkey.Key, error) { return nil, nil }`, true},
		"a crypto.Signer result":   {`func S() crypto.Signer { return nil }`, true},
		"a crypto.PrivateKey":      {`func P() crypto.PrivateKey { return nil }`, true},
		"a tls.Certificate":        {`func C() []tls.Certificate { return nil }`, true},
		"a *tls.Config":            {`func T() (int, *tls.Config) { return 0, nil }`, true},
		"a concrete signer":        {`func E() *ecdsa.PrivateKey { return nil }`, true},
		"a signer-shaped type":     {`type I interface{ crypto.Signer; Close() error }`, true},
		"an exported field":        {`type H struct{ Key crypto.Signer }; func New() *H { return nil }`, true},
		"a promoted field":         {`type H struct{ inner }; type inner struct{ Key crypto.Signer }`, true},
		"a map's value":            {`func M() map[string]crypto.Signer { return nil }`, true},
		"an exported variable":     {`var V crypto.Signer`, true},
		"a method's result":        {`type H struct{}; func (*H) Key() crypto.Signer { return nil }`, true},
		"an interface's method":    {`type I interface{ Key() crypto.Signer }`, true},
		"a callback's argument":    {`func F(use func(crypto.Signer)) {}`, true},
		"a pointer it can write":   {`func F(dst *crypto.Signer) {}`, true},
		"a slice it can write":     {`func F(dst []crypto.Signer) {}`, true},
		"a returned function":      {`func F() func() crypto.Signer { return nil }`, true},
		"an interface passed in":   {`type KeyUser interface{ Use(crypto.Signer) }; func Register(u KeyUser) {}`, true},
		"a channel's element":      {`func Keys() <-chan crypto.Signer { return nil }`, true},
		"an array's element":       {`func A() [1]crypto.Signer { return [1]crypto.Signer{} }`, true},
		"a callback variable":      {`var OnKey func(crypto.Signer)`, true},
		"a map's key":              {`func M() map[crypto.Signer]bool { return nil }`, true},
		"a handle's Sign method":   {`type LinkKey struct{ key *linkkey.Key }; func (*LinkKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }`, true},
		"an unexported field":      {`type H struct{ key crypto.Signer }; func New() *H { return nil }`, false},
		"an unexported method":     {`type H struct{}; func (H) key() crypto.Signer { return nil }`, false},
		"an unexported function":   {`func key() crypto.Signer { return nil }`, false},
		"a signer passed in":       {`func Use(s crypto.Signer) error { return nil }`, false},
		"the node's providers":     {`func Load(keys func(nodekey.Provider) (nodekey.Keys, error)) (pin string, err error) { return "", nil }`, false},
		"a public key":             {`func P() crypto.PublicKey { return nil }`, false},
		"an unexported type's use": {`type h struct{ Key crypto.Signer }; func use(*h) {}`, false},
		"an opaque handle":         {`type LinkKey struct{ key *linkkey.Key }; func (*LinkKey) Pin() string { return "" }; func Read() (*LinkKey, error) { return nil, nil }; func Dial(k *LinkKey, addr string) error { return nil }`, false},
	} {
		f, err := parser.ParseFile(srcFset, "x.go", head+c.src+"\n", 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pkg, err := (&types.Config{Importer: source()}).Check("x", srcFset, []*ast.File{f}, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := len(leaks(t, pkg)) > 0; got != c.want {
			t.Errorf("%s: found %v, want %v", name, got, c.want)
		}
	}
}
