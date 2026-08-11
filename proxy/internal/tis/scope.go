package tis

// Scope is the dimensioned task-scope descriptor (§5.2, normative algebra).
// Per-dimension partial order: set dimensions use subset order with "*" as top;
// Purpose uses equality with "*" as top. child ≤ parent iff child ≤ parent on
// EVERY dimension; anything not provably a narrowing is a widening and is
// rejected at derivation (confused-deputy control).
type Scope struct {
	Compartments  []string `json:"compartments"`
	ResourceTypes []string `json:"resource_types"`
	Actions       []string `json:"actions"`
	Purpose       string   `json:"purpose"`
}

// Narrows reports whether child ≤ parent on every dimension.
func Narrows(child, parent Scope) bool {
	return subsetOrTop(child.Compartments, parent.Compartments) &&
		subsetOrTop(child.ResourceTypes, parent.ResourceTypes) &&
		subsetOrTop(child.Actions, parent.Actions) &&
		(parent.Purpose == "*" || child.Purpose == parent.Purpose)
}

func subsetOrTop(child, parent []string) bool {
	if len(parent) == 1 && parent[0] == "*" {
		return true
	}
	// child "*" under a non-top parent is a widening
	for _, c := range child {
		if c == "*" {
			return false
		}
		found := false
		for _, p := range parent {
			if c == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
