// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

func CoverageFilter(source *ReportGeneratorWrapper, covCfg mgrconfig.CovFilterCfg,
	strict bool) (map[uint64]struct{}, map[string]uint64, error) {
	if covCfg.Empty() && covCfg.EmptyDFG() {
		return nil, nil, nil
	}
	rg, err := source.Get()
	if err != nil {
		return nil, nil, err
	}
	pcs := make(map[uint64]struct{})
	names := make(map[string]uint64)

	foreachSymbol := func(apply func(*backend.ObjectUnit)) {
		for _, sym := range rg.Symbols {
			apply(&sym.ObjectUnit)
		}
	}

	if err := covFilterAddFilter(pcs, covCfg.Functions, foreachSymbol, strict); err != nil {
		return nil, nil, err
	}
	foreachUnit := func(apply func(*backend.ObjectUnit)) {
		for _, unit := range rg.Units {
			apply(&unit.ObjectUnit)
		}
	}
	if err := covFilterAddFilter(pcs, covCfg.Files, foreachUnit, strict); err != nil {
		return nil, nil, err
	}
	if err := covFilterAddRawPCs(pcs, covCfg.RawPCs); err != nil {
		return nil, nil, err
	}
	// DGF
	if err := covFilterAddDirectedPcs(pcs, names, covCfg, foreachSymbol, strict); err != nil {
		return nil, nil, err
	}

	// Note that pcs may include both comparison and block/edge coverage callbacks.
	return pcs, names, nil
}

func covFilterAddFilter(pcs map[uint64]struct{}, filters []string, foreach func(func(*backend.ObjectUnit)),
	strict bool) error {
	res, err := compileRegexps(filters)
	if err != nil {
		return err
	}
	used := make(map[*regexp.Regexp][]string)
	foreach(func(unit *backend.ObjectUnit) {
		for _, re := range res {
			if re.MatchString(unit.Name) {
				// We add both coverage points and comparison interception points
				// because executor filters comparisons as well.
				for _, pc := range unit.PCs {
					pcs[pc] = struct{}{}
				}
				for _, pc := range unit.CMPs {
					pcs[pc] = struct{}{}
				}
				used[re] = append(used[re], unit.Name)
				break
			}
		}
	})
	for _, re := range res {
		sort.Strings(used[re])
		log.Logf(0, "coverage filter: %v: %v", re, used[re])
	}
	if strict && len(res) != len(used) {
		return fmt.Errorf("some filters don't match anything")
	}
	return nil
}

func covFilterAddRawPCs(pcs map[uint64]struct{}, rawPCsFiles []string) error {
	re := regexp.MustCompile(`(0x[0-9a-f]+)(?:: (0x[0-9a-f]+))?`)
	for _, f := range rawPCsFiles {
		rawFile, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("failed to open raw PCs file: %w", err)
		}
		defer rawFile.Close()
		s := bufio.NewScanner(rawFile)
		for s.Scan() {
			match := re.FindStringSubmatch(s.Text())
			if match == nil {
				return fmt.Errorf("bad line: %q", s.Text())
			}
			pc, err := strconv.ParseUint(match[1], 0, 64)
			if err != nil {
				return err
			}
			weight, err := strconv.ParseUint(match[2], 0, 32)
			if match[2] != "" && err != nil {
				return err
			}
			// If no weight is detected, set the weight to 0x1 by default.
			if match[2] == "" || weight < 1 {
				weight = 1
			}
			_ = weight // currently unused
			pcs[pc] = struct{}{}
		}
		if err := s.Err(); err != nil {
			return err
		}
	}
	return nil
}

func covFilterAddDirectedPcs(pcs map[uint64]struct{}, names map[string]uint64,
	covCfg mgrconfig.CovFilterCfg, foreach func(func(*backend.ObjectUnit)),
	strict bool) error {

	target_function := covCfg.TargetFunction
	tmp, paths := mgrconfig.FindShortestPaths(covCfg.CallGraph, target_function[0], 20)

	covCfg.TargetPaths = paths

	// Create unique function names list
	uniq_function_names_tmp := func(strings []string) []string {
		// Map to track seen strings
		seen := make(map[string]struct{})
		// Slice to store result
		var result []string

		// Iterate over each string
		for _, s := range strings {
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				result = append(result, s)
			}
		}
		return result
	}(tmp)

	// Add regex symbols to the list of functions to be covered
	processedStrings := func(strings []string) []string {
		processed := make([]string, len(strings))
		for i, s := range strings {
			processed[i] = "^" + s + "$"
		}
		return processed
	}(uniq_function_names_tmp)

	filters := processedStrings

	res, err := compileRegexps(filters)
	if err != nil {
		return err
	}

	uniq_function_names := []string{}

	used := make(map[*regexp.Regexp][]string)
	foreach(func(unit *backend.ObjectUnit) {
		for _, re := range res {
			if re.MatchString(unit.Name) {
				// We add both coverage points and comparison interception points
				// because executor filters comparisons as well.
				for _, pc := range unit.PCs {
					pcs[pc] = struct{}{}
					names[unit.Name] = pc
					log.Logf(0, "DGF: DEBUG: Adding %s:0x%x to the list of functions to be covered", unit.Name, pc)
				}
				for _, pc := range unit.CMPs {
					pcs[pc] = struct{}{}
				}
				used[re] = append(used[re], unit.Name)
				uniq_function_names = append(uniq_function_names, unit.Name)
				break
			}
		}
	})
	for _, re := range res {
		sort.Strings(used[re])
		log.Logf(0, "coverage filter: %v: %v", re, used[re])
	}
	if strict && len(res) != len(used) {
		//return fmt.Errorf("some filters don't match anything")
		log.Logf(0, "some filters don't match anything")
	}

	covCfg.Functions = uniq_function_names
	return nil
}

func compileRegexps(regexpStrings []string) ([]*regexp.Regexp, error) {
	var regexps []*regexp.Regexp
	for _, rs := range regexpStrings {
		r, err := regexp.Compile(rs)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		regexps = append(regexps, r)
	}
	return regexps, nil
}

type CoverageFilters struct {
	Areas          []corpus.FocusArea
	ExecutorFilter map[uint64]struct{}
	FunctionNames  map[string]uint64
	PathsByPC      map[uint64][]string
}

func PrepareCoverageFilters(source *ReportGeneratorWrapper, cfg *mgrconfig.Config,
	strict bool) (CoverageFilters, error) {
	var ret CoverageFilters
	needExecutorFilter := len(cfg.Experimental.FocusAreas) > 0

	for _, area := range cfg.Experimental.FocusAreas {
		pcs, names, err := CoverageFilter(source, area.Filter, strict)
		if err != nil {
			return ret, err
		}
		// KCOV will point to the next instruction, so we need to adjust the map.
		covPCs := make(map[uint64]struct{})
		for pc := range pcs {
			next := backend.NextInstructionPC(cfg.SysTarget, cfg.Type, pc)
			covPCs[next] = struct{}{}
		}
		// DGF: Set focus area to Corpaus.FocusArea definfed in pkg/corpus/corpus.go at line 42
		ret.Areas = append(ret.Areas, corpus.FocusArea{
			Name:      area.Name,
			CoverPCs:  covPCs,
			Weight:    area.Weight,
			Foobar:    area.Foobar,
			CallGraph: area.CallGraph,
		})
		if area.Filter.Empty() && area.Filter.EmptyDFG() {
			// An empty cover filter indicates that the user is interested in all the coverage.
			needExecutorFilter = false
		}
		ret.FunctionNames = names

		if len(area.Filter.TargetFunction) > 0 {
		}
	}
	if needExecutorFilter {
		ret.ExecutorFilter = map[uint64]struct{}{}
		for _, area := range ret.Areas {
			for pc := range area.CoverPCs {
				ret.ExecutorFilter[pc] = struct{}{}
			}
		}
	}
	return ret, nil
}
