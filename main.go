package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coontzy1/aquatone/agents"
	"github.com/coontzy1/aquatone/core"
	"github.com/coontzy1/aquatone/parsers"
	"github.com/google/uuid"
)

var (
	sess *core.Session
	err  error
)

func isURL(s string) bool {
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return false
	}
	return u.Scheme != ""
}

func hasSupportedScheme(s string) bool {
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func main() {
	// Initialize session
	if sess, err = core.NewSession(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Version flag
	if sess.Options.Version {
		fmt.Printf("%s v%s\n", core.Name, core.Version)
		os.Exit(0)
	}

	// Ensure output directory exists
	fi, err := os.Stat(sess.Options.OutDir)
	if os.IsNotExist(err) {
		sess.Out.Fatal("Output destination %s does not exist\n", sess.Options.OutDir)
		os.Exit(1)
	}
	if !fi.IsDir() {
		sess.Out.Fatal("Output destination must be a directory\n")
		os.Exit(1)
	}

	sess.Out.Important(
		"%s v%s started at %s\n\n",
		core.Name, core.Version,
		sess.Stats.StartedAt.Format(time.RFC3339),
	)

	// Load an existing session?
	if sess.Options.SessionPath != "" {
		data, err := ioutil.ReadFile(sess.Options.SessionPath)
		if err != nil {
			sess.Out.Fatal("Unable to read session file at %s: %s\n", sess.Options.SessionPath, err)
			os.Exit(1)
		}
		var parsed core.Session
		if err := json.Unmarshal(data, &parsed); err != nil {
			sess.Out.Fatal("Unable to parse session file at %s: %s\n", sess.Options.SessionPath, err)
			os.Exit(1)
		}
		sess.Out.Important("Loaded Aquatone session at %s\n", sess.Options.SessionPath)
		sess.Out.Debug("Session contains %d pages and %d similarity clusters\n",
			len(parsed.Pages), len(parsed.PageSimilarityClusters))
		sess.Out.Important("Generating HTML report...")

		// Pick template
		var tpl []byte
		if sess.Options.TemplatePath != "" {
			sess.Out.Debug("Using custom template: %s\n", sess.Options.TemplatePath)
			tpl, err = ioutil.ReadFile(sess.Options.TemplatePath)
		} else {
			sess.Out.Debug("Using default template: static/report_template.html\n")
			tpl, err = sess.Asset("static/report_template.html")
		}
		if err != nil {
			sess.Out.Fatal("Can't read report template file\n")
			os.Exit(1)
		}
		sess.Out.Debug("Template loaded successfully (%d bytes)\n", len(tpl))

		// Render HTML
		report := core.NewReport(&parsed, string(tpl))
		f, err := os.OpenFile(
			sess.GetFilePath("aquatone_report.html"),
			os.O_CREATE|os.O_RDWR,
			0644,
		)
		if err != nil {
			sess.Out.Fatal("Error during report generation: %s\n", err)
			os.Exit(1)
		}
		if err := report.Render(f); err != nil {
			sess.Out.Fatal("Error during report generation: %s\n", err)
			os.Exit(1)
		}
		f.Close()
		sess.Out.Important(" done\n\n")
		sess.Out.Important("Wrote HTML report to: %s\n\n", sess.GetFilePath("aquatone_report.html"))

		// Generate JSON of parsed.Pages
		jsonData, err := json.MarshalIndent(parsed.Pages, "", "  ")
		if err != nil {
			sess.Out.Error("Error generating JSON report: %s\n", err)
		} else {
			jsonFile := sess.GetFilePath("aquatone_report.json")
			if err := ioutil.WriteFile(jsonFile, jsonData, 0644); err != nil {
				sess.Out.Error("Error writing JSON report: %s\n", err)
			} else {
				sess.Out.Important("Wrote JSON report to: %s\n\n", jsonFile)
			}
		}
		os.Exit(0)
	}

	// Register agents
	agents.NewTCPPortScanner().Register(sess)
	agents.NewURLPublisher().Register(sess)
	agents.NewURLRequester().Register(sess)
	agents.NewURLHostnameResolver().Register(sess)
	agents.NewURLPageTitleExtractor().Register(sess)
	agents.NewURLScreenshotter().Register(sess)
	agents.NewURLTechnologyFingerprinter().Register(sess)
	agents.NewURLTakeoverDetector().Register(sess)
	agents.NewURLTlsChecker().Register(sess)

	// Prepare input reader
	var reader io.Reader
	if sess.Options.InputFile != "" {
		file, err := os.Open(sess.Options.InputFile)
		if err != nil {
			sess.Out.Fatal("Unable to open input file: %s\n", sess.Options.InputFile)
			os.Exit(1)
		}
		defer file.Close()
		reader = bufio.NewReader(file)
	} else {
		reader = bufio.NewReader(os.Stdin)
	}

	// Parse targets
	var targets []string
	if sess.Options.Nmap {
		parser := parsers.NewNmapParser(sess.Options.Ports, sess.Options.ShowDefaultPorts)
		targets, err = parser.Parse(reader)
	} else {
		parser := parsers.NewRegexParser()
		targets, err = parser.Parse(reader)
	}
	if err != nil {
		sess.Out.Fatal("Unable to parse input: %s\n", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		sess.Out.Fatal("No targets found in input.\n")
		os.Exit(1)
	}

	// Convert []int ports to []string for display
	portStrings := make([]string, len(sess.Ports))
	for i, p := range sess.Ports {
		portStrings[i] = fmt.Sprintf("%d", p)
	}

	// Summary
	sess.Out.Important(
		" :: Targets          : %d\n"+
			" :: Threads          : %d\n"+
			" :: Ports            : %s\n"+
			" :: Output Directory : %s\n\n",
		len(targets),
		sess.Options.Threads,
		strings.Join(portStrings, ", "),
		sess.Options.OutDir,
	)

	// Start scanning
	sess.EventBus.Publish(core.SessionStart)
	for _, tgt := range targets {
		if isURL(tgt) && hasSupportedScheme(tgt) {
			sess.EventBus.Publish(core.URL, tgt)
		} else {
			sess.EventBus.Publish(core.Host, tgt)
		}
	}

	time.Sleep(1 * time.Second)
	sess.EventBus.WaitAsync()
	sess.WaitGroup.Wait()

	sess.EventBus.Publish(core.SessionEnd)
	time.Sleep(1 * time.Second)
	sess.EventBus.WaitAsync()
	sess.WaitGroup.Wait()

	// Write URL list and compute structures
	sess.Out.Important("Calculating page structures...")
	urlFile, _ := os.OpenFile(
		sess.GetFilePath("aquatone_urls.txt"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)

	processedPages := 0
	totalPages := len(sess.Pages)
	sess.Out.Debug("Processing %d pages for structure calculation\n", totalPages)

	for _, page := range sess.Pages {
		processedPages++
		sess.Out.Debug("Processing page %d/%d: %s\n", processedPages, totalPages, page.URL)

		body, err := os.Open(sess.GetFilePath(fmt.Sprintf("html/%s.html", page.BaseFilename())))
		if err == nil {
			structure, err := core.GetPageStructure(body)
			body.Close()
			if err != nil {
				sess.Out.Debug("Error getting page structure for %s: %v\n", page.URL, err)
			} else {
				page.PageStructure = structure
				sess.Out.Debug("Page structure for %s: %d elements\n", page.URL, len(structure))
			}
			urlFile.WriteString(page.URL + "\n")
		} else {
			sess.Out.Debug("Could not open HTML file for %s: %v\n", page.URL, err)
		}
	}
	urlFile.Close()
	sess.Out.Important(" done\n")

	// Cluster pages
	sess.Out.Important("Clustering similar pages...")
	for _, page := range sess.Pages {
		if len(page.PageStructure) == 0 {
			sess.Out.Debug("Skipping page %s - no page structure available\n", page.URL)
			continue
		}

		assigned := false
		for id, cluster := range sess.PageSimilarityClusters {
			valid := true
			for _, u := range cluster {
				other := sess.GetPage(u)
				if other != nil && len(other.PageStructure) > 0 {
					similarity := core.GetSimilarity(page.PageStructure, other.PageStructure)
					sess.Out.Debug("Similarity between %s and %s: %.3f (threshold: %.3f)\n",
						page.URL, other.URL, similarity, sess.Options.Similarity)
					if similarity < sess.Options.Similarity {
						valid = false
						break
					}
				}
			}
			if valid {
				sess.PageSimilarityClusters[id] = append(cluster, page.URL)
				assigned = true
				sess.Out.Debug("Added %s to existing cluster %s\n", page.URL, id)
				break
			}
		}
		if !assigned {
			newClusterID := uuid.New().String()
			sess.PageSimilarityClusters[newClusterID] = []string{page.URL}
			sess.Out.Debug("Created new cluster %s for %s\n", newClusterID, page.URL)
		}
	}
	sess.Out.Important(" done\n")

	// Debug output for clustering results
	sess.Out.Debug("Clustering results:\n")
	totalClusters := len(sess.PageSimilarityClusters)
	totalPagesInClusters := len(sess.Pages)
	sess.Out.Debug("Total pages: %d\n", totalPagesInClusters)
	sess.Out.Debug("Total clusters: %d\n", totalClusters)

	clusterSizes := make([]int, 0, totalClusters)
	for id, cluster := range sess.PageSimilarityClusters {
		clusterSizes = append(clusterSizes, len(cluster))
		sess.Out.Debug("Cluster %s: %d pages\n", id, len(cluster))
	}

	if len(clusterSizes) > 0 {
		avgClusterSize := float64(totalPagesInClusters) / float64(totalClusters)
		sess.Out.Debug("Average cluster size: %.2f\n", avgClusterSize)
	}

	// Generate HTML report
	sess.Out.Important("Generating HTML report...")
	var tpl []byte
	if sess.Options.TemplatePath != "" {
		sess.Out.Debug("Using custom template: %s\n", sess.Options.TemplatePath)
		tpl, err = ioutil.ReadFile(sess.Options.TemplatePath)
	} else {
		sess.Out.Debug("Using default template: static/report_template.html\n")
		tpl, err = sess.Asset("static/report_template.html")
	}
	if err != nil {
		sess.Out.Fatal("Can't read report template file\n")
		os.Exit(1)
	}
	sess.Out.Debug("Template loaded successfully (%d bytes)\n", len(tpl))
	report := core.NewReport(sess, string(tpl))
	fHTML, err := os.OpenFile(
		sess.GetFilePath("aquatone_report.html"),
		os.O_CREATE|os.O_RDWR,
		0644,
	)
	if err != nil {
		sess.Out.Fatal("Error during report generation: %s\n", err)
		os.Exit(1)
	}
	if err := report.Render(fHTML); err != nil {
		sess.Out.Fatal("Error during report generation: %s\n", err)
		os.Exit(1)
	}
	fHTML.Close()
	sess.Out.Important(" done\n\n")
	sess.Out.Important("Wrote HTML report to: %s\n\n", sess.GetFilePath("aquatone_report.html"))

	// Generate JSON report
	sess.Out.Debug("Generating JSON report with %d pages and %d similarity clusters\n",
		len(sess.Pages), len(sess.PageSimilarityClusters))

	jsonOut, err := json.MarshalIndent(map[string]interface{}{
		"version":                core.Version,
		"stats":                  sess.Stats,
		"pages":                  sess.Pages,
		"pageSimilarityClusters": sess.PageSimilarityClusters,
		"scanInfo": map[string]interface{}{
			"ports":      sess.Ports,
			"threads":    sess.Options.Threads,
			"startedAt":  sess.Stats.StartedAt,
			"finishedAt": sess.Stats.FinishedAt,
			"duration":   sess.Stats.Duration().Milliseconds(),
		},
		"options": map[string]interface{}{
			"ports":             sess.Options.Ports,
			"threads":           sess.Options.Threads,
			"timeout":           sess.Options.Timeout,
			"scanTimeout":       sess.Options.ScanTimeout,
			"httpTimeout":       sess.Options.HTTPTimeout,
			"screenshotTimeout": sess.Options.ScreenshotTimeout,
			"screenshotDelay":   sess.Options.ScreenshotDelay,
			"similarity":        sess.Options.Similarity,
			"fullPage":          sess.Options.FullPage,
			"saveBody":          sess.Options.SaveBody,
			"followRedirect":    sess.Options.FollowRedirect,
			"silent":            sess.Options.Silent,
			"offline":           sess.Options.Offline,
			"nmap":              sess.Options.Nmap,
			"showDefaultPorts":  sess.Options.ShowDefaultPorts,
			"httpHeaders":       sess.Options.HTTPHeaders,
		},
	}, "", "  ")
	if err != nil {
		sess.Out.Error("Error generating JSON report: %s\n", err)
	} else {
		jsonFile := sess.GetFilePath("aquatone_report.json")
		if err := ioutil.WriteFile(jsonFile, jsonOut, 0644); err != nil {
			sess.Out.Error("Error writing JSON report: %s\n", err)
		} else {
			sess.Out.Important("Wrote JSON report to: %s\n\n", jsonFile)
		}
	}

	// Finalize session and output stats
	sess.End()
	sess.Out.Important("Writing session file...")
	if err := sess.SaveToFile("aquatone_session.json"); err != nil {
		sess.Out.Error("Failed to save session: %v\n", err)
	}

	sess.Out.Important("Time:\n")
	sess.Out.Info(" - Started at  : %v\n", sess.Stats.StartedAt.Format(time.RFC3339))
	sess.Out.Info(" - Finished at : %v\n", sess.Stats.FinishedAt.Format(time.RFC3339))
	sess.Out.Info(" - Duration    : %v\n\n", sess.Stats.Duration().Round(time.Second))

	sess.Out.Important("Requests:\n")
	sess.Out.Info(" - Successful : %v\n", sess.Stats.RequestSuccessful)
	sess.Out.Info(" - Failed     : %v\n\n", sess.Stats.RequestFailed)
	sess.Out.Info(" - 2xx : %v\n", sess.Stats.ResponseCode2xx)
	sess.Out.Info(" - 3xx : %v\n", sess.Stats.ResponseCode3xx)
	sess.Out.Info(" - 4xx : %v\n", sess.Stats.ResponseCode4xx)
	sess.Out.Info(" - 5xx : %v\n\n", sess.Stats.ResponseCode5xx)

	sess.Out.Important("Screenshots:\n")
	sess.Out.Info(" - Successful : %v\n", sess.Stats.ScreenshotSuccessful)
	sess.Out.Info(" - Failed     : %v\n\n", sess.Stats.ScreenshotFailed)

	sess.Out.Important("Wrote HTML report to: %s\n\n", sess.GetFilePath("aquatone_report.html"))
}
