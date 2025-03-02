// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cover provides types for working with coverage information (arrays of covered PCs).
package cover

type Cover map[uint64]struct{}

func FromRaw(raw []uint64) Cover {
	var c Cover
	c.Merge(raw)
	return c
}

func (cov *Cover) Merge(raw []uint64) {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	for _, pc := range raw {
		c[pc] = struct{}{}
	}
}

// Merge merges raw into coverage and returns newly added PCs. Overwrites/mutates raw.
func (cov *Cover) MergeDiff(raw []uint64) []uint64 {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	n := 0
	for _, pc := range raw {
		if _, ok := c[pc]; ok {
			continue
		}
		c[pc] = struct{}{}
		raw[n] = pc
		n++
	}
	return raw[:n]
}

func (cov *Cover) Serialize() []uint64 {
	res := make([]uint64, 0, len(*cov))
	for pc := range *cov {
		res = append(res, pc)
	}
	return res
}

// Diff calculates the difference between Cover and a slice of uint64.
func (c Cover) Diff(other []uint64) []uint64 {
	var diff []uint64
	otherSet := make(map[uint64]struct{})
	for _, pc := range other {
		otherSet[pc] = struct{}{}
	}
	for pc := range c {
		if _, exists := otherSet[pc]; !exists {
			diff = append(diff, pc)
		}
	}
	return diff
}
