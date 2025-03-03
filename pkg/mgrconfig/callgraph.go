package mgrconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

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

func (cfg *Config) calcurateShortestPath() int32 {
	return 0
}
