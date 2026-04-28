package output

import "penhunter/types"

type Handler interface {
	WriteResults(findings []*types.Finding) error
}

