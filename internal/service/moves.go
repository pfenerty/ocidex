package service

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Moves is the caller's upgrade queue: for each running image, the tag that
// removes the most criticals, then highs, and how long a better tag has been
// out; the criticals left once every upgrade is taken; and the same totals by
// namespace.
type Moves struct {
	// Source says where "running" came from: the caller's clusters, or, with
	// none connected, each owned artifact's newest tag.
	Source            string             `json:"source" enum:"cluster,owned"`
	Upgrades          []Upgrade          `json:"upgrades" doc:"Images with a better tag, longest waiting first"`
	LeftoverCriticals []LeftoverCritical `json:"leftoverCriticals" doc:"Criticals still running after every upgrade, highest CVSS first"`
	Namespaces        []NamespaceMoves   `json:"namespaces" doc:"Before/after totals per namespace, most criticals first"`
	Totals            MovesTotals        `json:"totals"`
}

// CritHigh is a critical and high count pair.
type CritHigh struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
}

func (c CritHigh) less(o CritHigh) bool {
	if c.Critical != o.Critical {
		return c.Critical < o.Critical
	}
	return c.High < o.High
}

func (c *CritHigh) add(o CritHigh) {
	c.Critical += o.Critical
	c.High += o.High
}

// MoveTag is one tag of an image.
type MoveTag struct {
	SbomID  string    `json:"sbomId"`
	Tag     string    `json:"tag"`
	Flavor  *string   `json:"flavor,omitempty"`
	BuiltAt time.Time `json:"builtAt" doc:"Image build date, else when the SBOM was ingested"`
}

// AlternativeTag is a tag of another flavor with fewer criticals than the
// same-flavor target.
type AlternativeTag struct {
	MoveTag
	After CritHigh `json:"after"`
}

// Upgrade is one running image with a better tag to move to.
type Upgrade struct {
	ArtifactID  string   `json:"artifactId"`
	Image       string   `json:"image"`
	Namespaces  []string `json:"namespaces"`
	Pods        int64    `json:"pods" doc:"Running pods; 0 without a cluster"`
	Running     MoveTag  `json:"running"`
	Target      MoveTag  `json:"target" doc:"Same-flavor tag with the fewest criticals, then highs; newest on a tie"`
	FirstBetter MoveTag  `json:"firstBetter" doc:"Oldest same-flavor tag better than the running one"`
	WaitingDays int      `json:"waitingDays" doc:"Days since firstBetter was built"`
	Before      CritHigh `json:"before"`
	After       CritHigh `json:"after"`
	// Alternative is set when another flavor's tag has fewer criticals than
	// Target (dex's -distroless line against its alpine one).
	Alternative *AlternativeTag `json:"alternative,omitempty"`
}

// LeftoverCritical is a critical CVE still present after every upgrade.
type LeftoverCritical struct {
	ID             string   `json:"id" doc:"Canonical vulnerability id"`
	CvssScore      *float32 `json:"cvssScore,omitempty"`
	Package        string   `json:"package"`
	PackageVersion string   `json:"packageVersion,omitempty"`
	FixedVersion   string   `json:"fixedVersion,omitempty" doc:"Upstream fix version no available tag ships yet"`
	FixState       string   `json:"fixState,omitempty" doc:"Matcher fix state: fixed, not-fixed, wont-fix or unknown"`
	Images         []string `json:"images" doc:"Images still carrying it"`
}

// NamespaceMoves totals the images running in one namespace.
type NamespaceMoves struct {
	Name   string   `json:"name"`
	Images int      `json:"images"`
	Pods   int64    `json:"pods"`
	Before CritHigh `json:"before"`
	After  CritHigh `json:"after"`
}

// MovesTotals sums the fleet. Before and After add up per-image counts, so a
// CVE in two images counts twice, as it is two things to upgrade.
type MovesTotals struct {
	Images            int      `json:"images"`
	Pods              int64    `json:"pods"`
	Before            CritHigh `json:"before"`
	After             CritHigh `json:"after"`
	Upgrades          int      `json:"upgrades"`
	UpgradesCutCrit   int      `json:"upgradesCutCritical" doc:"Upgrades that reduce criticals"`
	LongestWaitDays   int      `json:"longestWaitDays"`
	LongestWaitImage  string   `json:"longestWaitImage,omitempty"`
	LeftoverCriticals int      `json:"leftoverCriticals" doc:"Distinct critical CVEs left after every upgrade"`
}

// Move sources.
const (
	movesSourceCluster = "cluster"
	movesSourceOwned   = "owned"
)

// movesImage is one running SBOM and where it runs.
type movesImage struct {
	artifactID string
	name       string
	sbomID     pgtype.UUID
	podsByNS   map[string]int64
}

// moveCandidate is one SBOM an image could run.
type moveCandidate struct {
	id         pgtype.UUID
	version    string
	flavor     string
	arch       string
	major      pgtype.Int4
	minor      pgtype.Int4
	patch      pgtype.Int4
	prerelease bool
	builtAt    time.Time
	createdAt  time.Time
	counts     CritHigh
	settled    bool
}

func (c moveCandidate) tag() MoveTag {
	t := MoveTag{SbomID: c.id.String(), Tag: c.version, BuiltAt: c.builtAt}
	if c.flavor != "" {
		f := c.flavor
		t.Flavor = &f
	}
	return t
}

// compareMoveVersions orders two tags of one image: by version parts when both
// have them, else by build date.
func compareMoveVersions(a, b moveCandidate) int {
	if a.major.Valid && b.major.Valid {
		for _, p := range [][2]pgtype.Int4{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
			x, y := p[0].Int32, p[1].Int32
			if !p[0].Valid {
				x = -1
			}
			if !p[1].Valid {
				y = -1
			}
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		}
		return 0
	}
	switch {
	case a.builtAt.Before(b.builtAt):
		return -1
	case a.builtAt.After(b.builtAt):
		return 1
	}
	return 0
}

// GetMyMoves computes the caller's upgrade queue.
func (s *searchService) GetMyMoves(ctx context.Context, vis VisibilityFilter) (*Moves, error) {
	q := repository.New(s.db)
	userID, keyNS := uuidOrNull(vis.UserID), vis.keyNamespaces()

	clusters, err := q.CountMyClusters(ctx, repository.CountMyClustersParams{UserID: userID, KeyNamespaces: keyNS})
	if err != nil {
		return nil, fmt.Errorf("counting clusters: %w", err)
	}

	source := movesSourceOwned
	var images []*movesImage
	if clusters > 0 {
		source = movesSourceCluster
		rows, err := q.ListMyRunningImages(ctx, repository.ListMyRunningImagesParams{UserID: userID, KeyNamespaces: keyNS})
		if err != nil {
			return nil, fmt.Errorf("listing running images: %w", err)
		}
		bySBOM := map[pgtype.UUID]*movesImage{}
		for _, r := range rows {
			img := bySBOM[r.SbomID]
			if img == nil {
				img = &movesImage{artifactID: r.ArtifactID.String(), name: r.ArtifactName, sbomID: r.SbomID, podsByNS: map[string]int64{}}
				bySBOM[r.SbomID] = img
				images = append(images, img)
			}
			img.podsByNS[r.K8sNamespace] += r.PodCount
		}
	} else {
		rows, err := q.ListMyOwnedHeadlines(ctx, repository.ListMyOwnedHeadlinesParams{UserID: userID, KeyNamespaces: keyNS})
		if err != nil {
			return nil, fmt.Errorf("listing owned artifacts: %w", err)
		}
		for _, r := range rows {
			images = append(images, &movesImage{
				artifactID: r.ArtifactID.String(), name: r.ArtifactName, sbomID: r.SbomID,
				podsByNS: map[string]int64{r.NamespaceName: 0},
			})
		}
	}

	artifactIDs := make([]pgtype.UUID, 0, len(images))
	runningIDs := make([]pgtype.UUID, 0, len(images))
	seenArtifact := map[string]bool{}
	for _, img := range images {
		runningIDs = append(runningIDs, img.sbomID)
		if !seenArtifact[img.artifactID] {
			seenArtifact[img.artifactID] = true
			artifactIDs = append(artifactIDs, uuidOrNull(img.artifactID))
		}
	}

	candRows, err := q.ListUpgradeCandidates(ctx, repository.ListUpgradeCandidatesParams{
		ArtifactIds: artifactIDs, RunningIds: runningIDs, UserID: userID, KeyNamespaces: keyNS,
	})
	if err != nil {
		return nil, fmt.Errorf("listing upgrade candidates: %w", err)
	}
	byArtifact := map[string][]moveCandidate{}
	for _, r := range candRows {
		built := r.CreatedAt.Time
		if t, err := time.Parse(time.RFC3339Nano, r.BuildDate); err == nil {
			built = t
		}
		byArtifact[r.ArtifactID.String()] = append(byArtifact[r.ArtifactID.String()], moveCandidate{
			id: r.ID, version: r.SubjectVersion, flavor: r.Flavor, arch: r.Architecture,
			major: r.VersionMajor, minor: r.VersionMinor, patch: r.VersionPatch, prerelease: r.VersionPrerelease,
			builtAt: built, createdAt: r.CreatedAt.Time,
			counts: CritHigh{Critical: r.Critical, High: r.High}, settled: r.Settled,
		})
	}

	plans := planMoves(images, byArtifact)

	postIDs := make([]pgtype.UUID, 0, len(plans))
	for _, p := range plans {
		postIDs = append(postIDs, p.post)
	}
	findings, err := q.ListCriticalFindings(ctx, postIDs)
	if err != nil {
		return nil, fmt.Errorf("listing critical findings: %w", err)
	}

	return buildMoves(source, plans, findings, time.Now()), nil
}

// movePlan is what happens to one running image: its upgrade, if any, and the
// SBOM it runs afterwards.
type movePlan struct {
	img     *movesImage
	before  CritHigh
	upgrade *Upgrade // nil when no better tag exists
	post    pgtype.UUID
	after   CritHigh
}

// planMoves picks each image's target. An image whose running SBOM is not
// among the candidates (none visible) is left out.
func planMoves(images []*movesImage, byArtifact map[string][]moveCandidate) []movePlan {
	plans := make([]movePlan, 0, len(images))
	for _, img := range images {
		if plan, ok := planImage(img, byArtifact[img.artifactID]); ok {
			plans = append(plans, plan)
		}
	}
	return plans
}

func planImage(img *movesImage, cands []moveCandidate) (movePlan, bool) {
	var running moveCandidate
	found := false
	for _, c := range cands {
		if c.id == img.sbomID {
			running, found = c, true
			break
		}
	}
	if !found {
		return movePlan{}, false
	}
	plan := movePlan{img: img, before: running.counts, post: running.id, after: running.counts}

	same, other := upgradeCandidates(running, cands)
	best, first := bestOf(same), firstBetter(same, running.counts)
	if best == nil || first == nil || !best.counts.less(running.counts) {
		return plan, true
	}
	up := &Upgrade{
		ArtifactID: img.artifactID, Image: img.name,
		Running: running.tag(), Target: best.tag(), FirstBetter: first.tag(),
		Before: running.counts, After: best.counts,
	}
	if alt := bestOf(other); alt != nil && alt.counts.Critical < best.counts.Critical {
		up.Alternative = &AlternativeTag{MoveTag: alt.tag(), After: alt.counts}
	}
	plan.upgrade, plan.post, plan.after = up, best.id, best.counts
	return plan, true
}

// upgradeCandidates returns the tags running could move to, split by whether
// they share its flavor, each sorted oldest first so the first better tag is
// the first match and a tie on counts resolves to the newest. Candidates are
// on the same architecture, newer, vuln-matched, and stable unless running is
// a prerelease; one per (tag, flavor), the latest ingested.
func upgradeCandidates(running moveCandidate, cands []moveCandidate) (same, other []moveCandidate) {
	latest := map[[2]string]moveCandidate{}
	for _, c := range cands {
		if c.arch != running.arch || !c.settled || (c.prerelease && !running.prerelease) ||
			compareMoveVersions(c, running) <= 0 {
			continue
		}
		k := [2]string{c.version, c.flavor}
		if prev, ok := latest[k]; !ok || c.createdAt.After(prev.createdAt) {
			latest[k] = c
		}
	}
	for _, c := range latest {
		if c.flavor == running.flavor {
			same = append(same, c)
		} else {
			other = append(other, c)
		}
	}
	for _, cs := range [][]moveCandidate{same, other} {
		sort.Slice(cs, func(i, j int) bool {
			if cmp := compareMoveVersions(cs[i], cs[j]); cmp != 0 {
				return cmp < 0
			}
			return cs[i].version < cs[j].version
		})
	}
	return same, other
}

// bestOf returns the candidate with the fewest criticals, then highs, newest
// on a tie. cs is sorted oldest first.
func bestOf(cs []moveCandidate) *moveCandidate {
	var best *moveCandidate
	for i := range cs {
		if best == nil || !best.counts.less(cs[i].counts) {
			best = &cs[i]
		}
	}
	return best
}

// firstBetter returns the oldest candidate better than than. cs is sorted
// oldest first.
func firstBetter(cs []moveCandidate, than CritHigh) *moveCandidate {
	for i := range cs {
		if cs[i].counts.less(than) {
			return &cs[i]
		}
	}
	return nil
}

// buildMoves assembles the report from the plans and the post-upgrade SBOMs'
// critical findings.
func buildMoves(source string, plans []movePlan, findings []repository.ListCriticalFindingsRow, now time.Time) *Moves {
	out := &Moves{
		Source:            source,
		Upgrades:          []Upgrade{},
		LeftoverCriticals: []LeftoverCritical{},
		Namespaces:        []NamespaceMoves{},
	}
	nsTotals := map[string]*NamespaceMoves{}
	imagesByPost := map[pgtype.UUID][]string{}

	for _, p := range plans {
		var pods int64
		namespaces := make([]string, 0, len(p.img.podsByNS))
		for ns, n := range p.img.podsByNS {
			pods += n
			namespaces = append(namespaces, ns)
			t := nsTotals[ns]
			if t == nil {
				t = &NamespaceMoves{Name: ns}
				nsTotals[ns] = t
			}
			t.Images++
			t.Pods += n
			t.Before.add(p.before)
			t.After.add(p.after)
		}
		sort.Strings(namespaces)

		out.Totals.Images++
		out.Totals.Pods += pods
		out.Totals.Before.add(p.before)
		out.Totals.After.add(p.after)
		imagesByPost[p.post] = append(imagesByPost[p.post], p.img.name)

		if p.upgrade == nil {
			continue
		}
		up := *p.upgrade
		up.Namespaces = namespaces
		up.Pods = pods
		up.WaitingDays = max(0, int(now.Sub(up.FirstBetter.BuiltAt).Hours()/24))
		out.Upgrades = append(out.Upgrades, up)
		out.Totals.Upgrades++
		if up.After.Critical < up.Before.Critical {
			out.Totals.UpgradesCutCrit++
		}
		if up.WaitingDays > out.Totals.LongestWaitDays || out.Totals.LongestWaitImage == "" {
			out.Totals.LongestWaitDays, out.Totals.LongestWaitImage = up.WaitingDays, up.Image
		}
	}

	sort.SliceStable(out.Upgrades, func(i, j int) bool {
		a, b := out.Upgrades[i], out.Upgrades[j]
		if a.WaitingDays != b.WaitingDays {
			return a.WaitingDays > b.WaitingDays
		}
		if da, db := a.Before.Critical-a.After.Critical, b.Before.Critical-b.After.Critical; da != db {
			return da > db
		}
		return a.Image < b.Image
	})

	for _, t := range nsTotals {
		out.Namespaces = append(out.Namespaces, *t)
	}
	sort.Slice(out.Namespaces, func(i, j int) bool {
		a, b := out.Namespaces[i], out.Namespaces[j]
		if a.Before.Critical != b.Before.Critical {
			return a.Before.Critical > b.Before.Critical
		}
		return a.Name < b.Name
	})

	out.LeftoverCriticals = leftoverCriticals(findings, imagesByPost)
	out.Totals.LeftoverCriticals = len(out.LeftoverCriticals)
	return out
}

// leftoverCriticals groups the post-upgrade findings by CVE across images.
func leftoverCriticals(findings []repository.ListCriticalFindingsRow, imagesByPost map[pgtype.UUID][]string) []LeftoverCritical {
	byID := map[string]*LeftoverCritical{}
	seen := map[string]map[string]bool{}
	for _, f := range findings {
		lc := byID[f.CanonicalID]
		if lc == nil {
			lc = &LeftoverCritical{
				ID: f.CanonicalID, Package: f.PackageName, PackageVersion: f.PackageVersion,
				FixedVersion: f.FixedVersion, FixState: f.FixState, Images: []string{},
			}
			if f.CvssScore >= 0 {
				score := f.CvssScore
				lc.CvssScore = &score
			}
			byID[f.CanonicalID] = lc
			seen[f.CanonicalID] = map[string]bool{}
		}
		for _, name := range imagesByPost[f.SbomID] {
			if !seen[f.CanonicalID][name] {
				seen[f.CanonicalID][name] = true
				lc.Images = append(lc.Images, name)
			}
		}
	}
	out := make([]LeftoverCritical, 0, len(byID))
	for _, lc := range byID {
		sort.Strings(lc.Images)
		out = append(out, *lc)
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := float32(-1), float32(-1)
		if out[i].CvssScore != nil {
			si = *out[i].CvssScore
		}
		if out[j].CvssScore != nil {
			sj = *out[j].CvssScore
		}
		if si != sj {
			return si > sj
		}
		return out[i].ID < out[j].ID
	})
	return out
}
