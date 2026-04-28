package output

import "github.com/cc1a2b/PenHunter/types"

type Handler interface {
	WriteResults(findings []*types.Finding) error
}

