// Building the backend-computed dependency diff tree of ADR-0021: roots,
// isDirect, nodeRef, and the descendantChanges rollup the frontend renders
// without recomputing. Split out of changelog.go.

package service

import (
	"sort"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// buildDepEdgeMaps constructs in-edge count and outgoing-edges adjacency from a dep list.
func buildDepEdgeMaps(deps []repository.ListDependenciesBySBOMRow) (inEdge map[string]int, outEdges map[string][]string) {
	inEdge = make(map[string]int, len(deps))
	outEdges = make(map[string][]string, len(deps))
	for _, d := range deps {
		inEdge[d.DependsOn]++
		outEdges[d.Ref] = append(outEdges[d.Ref], d.DependsOn)
	}
	return
}

// computeRootsAndDirect returns the ordered root bom-refs and the set of direct
// (one-hop-from-synthetic-root) bom-refs, given the edge maps and metadata bom-ref.
func computeRootsAndDirect(outEdges map[string][]string, inEdge map[string]int, metaBomRef string, toPkgs []repository.ListSBOMPackagesRow) (roots []string, directSet map[string]bool) {
	directSet = make(map[string]bool)
	if metaBomRef != "" && len(outEdges[metaBomRef]) > 0 {
		roots = make([]string, len(outEdges[metaBomRef]))
		copy(roots, outEdges[metaBomRef])
		for _, child := range roots {
			directSet[child] = true
		}
	} else {
		for _, p := range toPkgs {
			if p.BomRef.Valid && p.BomRef.String != metaBomRef && inEdge[p.BomRef.String] == 0 {
				roots = append(roots, p.BomRef.String)
			}
		}
	}
	bomRefName := make(map[string]string, len(toPkgs))
	for _, p := range toPkgs {
		if p.BomRef.Valid {
			bomRefName[p.BomRef.String] = p.Name
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		ni, nj := bomRefName[roots[i]], bomRefName[roots[j]]
		if ni != nj {
			return ni < nj
		}
		return roots[i] < roots[j]
	})
	return
}

// buildNodeLookups returns lookup maps: purl→nodeID, (name+\x00+group)→nodeID, bomRef→nodeID.
func buildNodeLookups(toPkgs []repository.ListSBOMPackagesRow) (nodeByPurl, nodeByNameGroup, bomRefToID map[string]string) {
	nodeByPurl = make(map[string]string, len(toPkgs))
	nodeByNameGroup = make(map[string]string, len(toPkgs))
	bomRefToID = make(map[string]string, len(toPkgs))
	for _, p := range toPkgs {
		id := uuidToString(p.ID)
		if p.Purl.Valid && p.Purl.String != "" {
			nodeByPurl[p.Purl.String] = id
		}
		nodeByNameGroup[p.Name+"\x00"+p.GroupName.String] = id
		if p.BomRef.Valid {
			bomRefToID[p.BomRef.String] = id
		}
	}
	return
}

// annotateNodeRefs sets NodeRef on each change by purl-first, name+group fallback.
func annotateNodeRefs(changes []ComponentDiff, nodeByPurl, nodeByNameGroup map[string]string) {
	for i := range changes {
		c := &changes[i]
		if c.Purl != nil && *c.Purl != "" {
			if id, ok := nodeByPurl[*c.Purl]; ok {
				idCopy := id
				c.NodeRef = &idCopy
				continue
			}
		}
		ng := c.Name + "\x00"
		if c.Group != nil {
			ng = c.Name + "\x00" + *c.Group
		}
		if id, ok := nodeByNameGroup[ng]; ok {
			idCopy := id
			c.NodeRef = &idCopy
		}
	}
}

// buildIDToChildren converts the bom-ref adjacency into a node-ID adjacency.
func buildIDToChildren(outEdges map[string][]string, bomRefToID map[string]string) map[string][]string {
	idToChildren := make(map[string][]string, len(bomRefToID))
	for bomRef, children := range outEdges {
		parentID, ok := bomRefToID[bomRef]
		if !ok {
			continue
		}
		for _, childRef := range children {
			if childID, ok2 := bomRefToID[childRef]; ok2 {
				idToChildren[parentID] = append(idToChildren[parentID], childID)
			}
		}
	}
	return idToChildren
}

// buildChangesByNodeID returns a map of nodeID → []direction for all changes with a NodeRef.
func buildChangesByNodeID(changes []ComponentDiff) map[string][]string {
	m := make(map[string][]string, len(changes))
	for _, c := range changes {
		if c.NodeRef != nil {
			m[*c.NodeRef] = append(m[*c.NodeRef], c.Direction)
		}
	}
	return m
}

// buildNodes constructs the ComponentSummary slice with IsDirect and DescendantChanges set.
func buildNodes(toPkgs []repository.ListSBOMPackagesRow, toID pgtype.UUID, directSet map[string]bool, idToChildren map[string][]string, changesByNodeID map[string][]string) []ComponentSummary {
	nodes := make([]ComponentSummary, 0, len(toPkgs))
	for _, p := range toPkgs {
		node := toComponentSummary(p.ID, toID, p.BomRef, p.Type, p.Name, p.GroupName, p.Version, p.Purl)
		if p.BomRef.Valid {
			node.IsDirect = directSet[p.BomRef.String]
		}
		nodes = append(nodes, node)
	}
	for i, n := range nodes {
		counts := dfsChangeCounts(n.ID, idToChildren, changesByNodeID, make(map[string]bool))
		if counts != (ChangeCounts{}) {
			nodes[i].DescendantChanges = &counts
		}
	}
	return nodes
}

// dfsChangeCounts aggregates change direction counts for a node's transitive descendants.
// Each DFS call uses its own visited set so a node is counted once per ancestor even
// when reachable via multiple paths (cycle-safe).
func dfsChangeCounts(nodeID string, idToChildren map[string][]string, changesByNodeID map[string][]string, visited map[string]bool) ChangeCounts {
	var counts ChangeCounts
	for _, childID := range idToChildren[nodeID] {
		if visited[childID] {
			continue
		}
		visited[childID] = true
		for _, dir := range changesByNodeID[childID] {
			addDirectionCount(&counts, dir)
		}
		sub := dfsChangeCounts(childID, idToChildren, changesByNodeID, visited)
		counts.Added += sub.Added
		counts.Removed += sub.Removed
		counts.Upgraded += sub.Upgraded
		counts.Downgraded += sub.Downgraded
		counts.Modified += sub.Modified
	}
	return counts
}
