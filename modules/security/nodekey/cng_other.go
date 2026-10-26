//go:build !windows

package nodekey

import (
	"crypto"
	"errors"
)

var errNoCNG = errors.New("nodekey: CNG keys are Windows only")

func (CNG) Create(string) (crypto.Signer, error) { return nil, errNoCNG }
func (CNG) Open(string) (crypto.Signer, error)   { return nil, errNoCNG }
func (CNG) Delete(string) error                  { return errNoCNG }
func (CNG) Restrict(string) error                { return errNoCNG }
