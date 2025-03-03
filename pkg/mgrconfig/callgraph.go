package mgrconfig

import (
	"container/list"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/simple"
)

type Node struct {
	ID string `json:"id"`
}

type Link struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type GraphData struct {
	Directed   bool     `json:"directed"`
	Multigraph bool     `json:"multigraph"`
	Graph      struct{} `json:"graph"`
	Nodes      []Node   `json:"nodes"`
	Links      []Link   `json:"links"`
}

type CallGraph struct {
	Graph   *simple.DirectedGraph
	NodeMap map[string]simple.Node
}

// loadCallGraph reads a JSON file and creates a call graph.
func (cfg *Config) loadCallGraph() (*CallGraph, error) {
	// Open and read the JSON file
	file, err := os.Open(cfg.Experimental.DirectedGreyboxFuzzing.GraphFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	byteValue, _ := io.ReadAll(file)

	var graphData GraphData
	json.Unmarshal(byteValue, &graphData)

	g := simple.NewDirectedGraph()

	nodeMap := make(map[string]simple.Node)
	for _, node := range graphData.Nodes {
		n := g.NewNode()
		g.AddNode(n)
		nodeMap[node.ID] = n.(simple.Node)
	}

	for _, link := range graphData.Links {
		if link.Source == link.Target {
			// Skip self edges
			continue
		}
		sourceNode := nodeMap[link.Source]
		targetNode := nodeMap[link.Target]
		g.SetEdge(g.NewEdge(sourceNode, targetNode))
	}

	return &CallGraph{Graph: g, NodeMap: nodeMap}, nil
}

// findShortestPaths finds shortest paths leading to the target node using BFS, limited to maxPaths.
func findShortestPaths(g *CallGraph, target string, maxPaths int) [][]graph.Node {
	var paths [][]graph.Node
	queue := list.New()
	pathCount := 0

	if targetNode, ok := g.NodeMap[target]; ok {
		queue.PushBack([]graph.Node{targetNode})

		for queue.Len() > 0 && pathCount < maxPaths {
			currentPath := queue.Remove(queue.Front()).([]graph.Node)
			currentNode := currentPath[len(currentPath)-1]

			// If we've reached a source node, add the path
			if g.Graph.To(currentNode.ID()) == nil || g.Graph.To(currentNode.ID()).Len() == 0 {
				paths = append(paths, currentPath)
				pathCount++
				if pathCount >= maxPaths {
					fmt.Printf("Path limit (%d) reached. Stopping exploration.\n", maxPaths)
					break
				}
			}

			// Add predecessors to the queue
			for neighbors := g.Graph.To(currentNode.ID()); neighbors.Next(); {
				predecessor := neighbors.Node()
				// Avoid cycles
				if !containsNode(currentPath, predecessor) {
					newPath := append([]graph.Node{}, currentPath...)
					newPath = append(newPath, predecessor)
					queue.PushBack(newPath)
				}
			}
		}
	}

	fmt.Printf("Found %d paths\n", len(paths))
	return paths
}

// containsNode checks if a node is in the given path
func containsNode(path []graph.Node, node graph.Node) bool {
	for _, n := range path {
		if n.ID() == node.ID() {
			return true
		}
	}
	return false
}

// printPaths prints all paths in a readable format.
func printPaths(paths [][]graph.Node, g *CallGraph) {
	for _, path := range paths {
		for i := len(path) - 1; i >= 0; i-- { // Reverse the path for printing source-to-target
			for id, n := range g.NodeMap {
				if n.ID() == path[i].ID() {
					fmt.Print(id)
					if i > 0 {
						fmt.Print(" -> ")
					}
					break
				}
			}
		}
		fmt.Println()
	}
}

func (cfg *Config) calcurateShortestPath() int64 {
	return 0
}
