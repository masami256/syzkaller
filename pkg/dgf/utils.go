package dgf

import (
	"fmt"
	"runtime"
)

func ShowStackTrace() {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	fmt.Printf("---------------------")
	fmt.Printf("stack trace:\n %s", string(buf[:n]))
}

func StringMapToStringList(maps map[string]string) []string {
	// Create unique function names list
	ret := func(stringMap map[string]string) []string {
		// Slice to store result
		var result []string

		// Iterate over each key in the map
		for key := range stringMap {
			result = append(result, key)
		}

		return result
	}(maps)

	return ret
}

func CreateRegrepStrings(functions []string) []string {
	// Create unique function names list
	ret := func(stringList []string) []string {
		// Slice to store result
		var result []string

		// Iterate over each key in the map
		for _, name := range stringList {
			result = append(result, fmt.Sprintf("^%s$", name))
		}

		return result
	}(functions)

	return ret
}
