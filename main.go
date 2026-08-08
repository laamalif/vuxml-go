package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/fatih/color"
	"github.com/hashicorp/go-version"
	"github.com/jaytaylor/html2text"
	"github.com/ulikunitz/xz"
)

const (
	LATEST_VUXML = "https://www.vuxml.org/freebsd/vuln.xml.xz"
	VERSION      = "1.3.0"
)

// Vuln represents a single vulnerability entry, parsed from etree.
type Vuln struct {
	Vid         string
	Topic       string
	Description string
	References  []struct {
		Source string
		Value  string
	}
	Affects []struct {
		Name  string
		Range []struct {
			Lt string
			Le string
			Eq string
			Ge string
			Gt string
		}
	}
	Dates struct {
		Discovery string
		Entry     string
		Modified  string
	}
}

// isValidDate checks if a string is a valid date in YYYY, YYYY-MM, or YYYY-MM-DD format.
func isValidDate(dateStr string) bool {
	layouts := []string{"2006", "2006-01", "2006-01-02"}
	for _, layout := range layouts {
		if _, err := time.Parse(layout, dateStr); err == nil {
			return true
		}
	}
	return false
}

// cleanVersion prepares a version string for parsing by the go-version library.
func cleanVersion(v string) string {
	// We don't handle PORTEPOCH
	if strings.Contains(v, ",") {
		v = strings.Split(v, ",")[0]
	}
	// PORTREVISION is treated as a sub-version
	v = strings.ReplaceAll(v, "_", ".")
	// version.* is treated as version
	v = strings.ReplaceAll(v, ".*", "")
	return v
}

// printVuln displays a single vulnerability in a user-friendly format.
func printVuln(vuln Vuln, showDescription bool) {
	bold := color.New(color.Bold).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	redBg := color.New(color.BgRed).SprintFunc()

	fmt.Printf("%s %s\n", bold("Vulnerability ID:"), vuln.Vid)
	fmt.Printf("  %s %s\n", bold("Topic:"), redBg(vuln.Topic))

	if len(vuln.Affects) > 0 {
		fmt.Printf("  %s\n", bold("Affects:"))
		for _, pkg := range vuln.Affects {
			fmt.Printf("    %s:\n", bold(red(pkg.Name)))
			for _, r := range pkg.Range {
				var conditions []string
				if r.Lt != "" {
					conditions = append(conditions, "< "+r.Lt)
				}
				if r.Le != "" {
					conditions = append(conditions, "<= "+r.Le)
				}
				if r.Eq != "" {
					conditions = append(conditions, "== "+r.Eq)
				}
				if r.Ge != "" {
					conditions = append(conditions, ">= "+r.Ge)
				}
				if r.Gt != "" {
					conditions = append(conditions, "> "+r.Gt)
				}
				fmt.Printf("      %s\n", strings.Join(conditions, " ; "))
			}
		}
	}

	if showDescription {
		fmt.Printf("  %s\n", bold("Description:"))
		text, err := html2text.FromString(vuln.Description, html2text.Options{PrettyTables: true})
		if err != nil {
			// fallback to just printing the description
			text = vuln.Description
		}
		for _, line := range strings.Split(text, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}

	if len(vuln.References) > 0 {
		fmt.Printf("  %s\n", bold("References:"))
		for _, ref := range vuln.References {
			fmt.Printf("    %s: %s\n", ref.Source, ref.Value)
		}
	}

	if (vuln.Dates != struct{ Discovery, Entry, Modified string }{}) {
		if vuln.Dates.Discovery != "" {
			fmt.Printf("  %s %s\n", bold("Discovery date:"), vuln.Dates.Discovery)
		}
		if vuln.Dates.Entry != "" {
			fmt.Printf("  %s %s\n", bold("Entry date:"), vuln.Dates.Entry)
		}
		if vuln.Dates.Modified != "" {
			fmt.Printf("  %s %s\n", bold("Modified date:"), vuln.Dates.Modified)
		}
	}
	fmt.Println()
}

// getCacheDir determines the appropriate cache directory based on environment variables.
func getCacheDir() (string, error) {
	var cacheDir string
	if homeCache, err := os.UserCacheDir(); err == nil {
		cacheDir = homeCache + "/vuxml"
	} else if tmpDir := os.Getenv("TMPDIR"); tmpDir != "" {
		cacheDir = tmpDir + "/.cache/vuxml"
	} else if tmp := os.Getenv("TMP"); tmp != "" {
		cacheDir = tmp + "/.cache/vuxml"
	} else {
		return "", fmt.Errorf("could not determine cache directory")
	}

	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			return "", fmt.Errorf("unable to create cache directory: %w", err)
		}
	}

	return cacheDir, nil
}

// downloadVuXML downloads and caches the latest FreeBSD VuXML file.
func downloadVuXML() (string, error) {
	vuxmlCacheDir, err := getCacheDir()
	if err != nil {
		return "", err
	}

	filePath := vuxmlCacheDir + "/vuln.xml"
	fileInfo, err := os.Stat(filePath)
	if err == nil && time.Since(fileInfo.ModTime()) < 24*time.Hour {
		return filePath, nil
	}

	fmt.Println("Downloading latest VuXML database...")
	resp, err := http.Get(LATEST_VUXML)
	if err != nil {
		return "", fmt.Errorf("failed to download VuXML file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download VuXML file: received status code %d", resp.StatusCode)
	}

	xzReader, err := xz.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to create xz reader: %w", err)
	}

	xmlData, err := io.ReadAll(xzReader)
	if err != nil {
		return "", fmt.Errorf("failed to read XML data: %w", err)
	}

	err = os.WriteFile(filePath, xmlData, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write cache file: %w", err)
	}

	return filePath, nil
}

func main() {
	// Define command-line flags
	id := flag.String("id", "", "Search for the specified Vulnerability ID")
	topic := flag.String("topic", "", "Search for the specified regex in topics")
	keyword := flag.String("keyword", "", "Search for the specified regex in topics and descriptions")
	pkg := flag.String("package", "", "Search for the specified name in affected packages (name~version)")
	reNames := flag.Bool("re-names", false, "The name part of a PID is a regex")
	ref := flag.String("ref", "", "Search for the specified ID in references (source~ID)")
	listSources := flag.Bool("sources", false, "List references sources")
	discovery := flag.String("discovery", "", "Search for the specified date in discovery dates")
	entry := flag.String("entry", "", "Search for the specified date in entry dates")
	modified := flag.String("modified", "", "Search for the specified date in modified dates")
	showVersion := flag.Bool("version", false, "Print version and exit")
	showDesc := flag.Bool("desc", false, "Print description")
	latest := flag.Int("latest", 0, "Show the N latest vulnerabilities")
	flag.Parse()

	if *showVersion {
		fmt.Printf("vuxml-go version %s\n", VERSION)
		os.Exit(0)
	}

	// If no flags are specified, print the help message and exit
	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(0)
	}

	// 1. Get the VuXML file (from cache or download)
	xmlPath, err := downloadVuXML()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// 2. Read the XML data
	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		log.Fatalf("Failed to read XML data from cache: %v", err)
	}

	// 3. Parse the XML with etree
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		log.Fatalf("Failed to parse XML: %v", err)
	}

	var vulns []Vuln
	root := doc.SelectElement("vuxml")
	for _, vulnElement := range root.SelectElements("vuln") {
		if vulnElement.SelectElement("cancelled") != nil {
			continue
		}

		vid := vulnElement.SelectAttrValue("vid", "")
		description := ""
		if descEl := vulnElement.SelectElement("description"); descEl != nil {
			description = descEl.Text()
		}
		topic := ""
		if topicEl := vulnElement.SelectElement("topic"); topicEl != nil {
			topic = topicEl.Text()
		}

		vuln := Vuln{
			Vid:         vid,
			Topic:       topic,
			Description: description,
		}

		// Dates
		if datesElement := vulnElement.SelectElement("dates"); datesElement != nil {
			if discoveryEl := datesElement.SelectElement("discovery"); discoveryEl != nil {
				vuln.Dates.Discovery = discoveryEl.Text()
			}
			if entryEl := datesElement.SelectElement("entry"); entryEl != nil {
				vuln.Dates.Entry = entryEl.Text()
			}
			if modifiedEl := datesElement.SelectElement("modified"); modifiedEl != nil {
				vuln.Dates.Modified = modifiedEl.Text()
			}
		}

		// Affects
		if affectsElement := vulnElement.SelectElement("affects"); affectsElement != nil {
			for _, pkgElement := range affectsElement.SelectElements("package") {
				name := ""
				if nameEl := pkgElement.SelectElement("name"); nameEl != nil {
					name = nameEl.Text()
				}
				p := struct {
					Name  string
					Range []struct{ Lt, Le, Eq, Ge, Gt string }
				}{
					Name: name,
				}
				for _, rangeElement := range pkgElement.SelectElements("range") {
					r := struct{ Lt, Le, Eq, Ge, Gt string }{}
					if ltEl := rangeElement.SelectElement("lt"); ltEl != nil {
						r.Lt = ltEl.Text()
					}
					if leEl := rangeElement.SelectElement("le"); leEl != nil {
						r.Le = leEl.Text()
					}
					if eqEl := rangeElement.SelectElement("eq"); eqEl != nil {
						r.Eq = eqEl.Text()
					}
					if geEl := rangeElement.SelectElement("ge"); geEl != nil {
						r.Ge = geEl.Text()
					}
					if gtEl := rangeElement.SelectElement("gt"); gtEl != nil {
						r.Gt = gtEl.Text()
					}
					p.Range = append(p.Range, r)
				}
				vuln.Affects = append(vuln.Affects, p)
			}
		}

		// References
		if referencesElement := vulnElement.SelectElement("references"); referencesElement != nil {
			for _, refElement := range referencesElement.ChildElements() {
				r := struct {
					Source string
					Value  string
				}{
					Source: refElement.Tag,
					Value:  refElement.Text(),
				}
				vuln.References = append(vuln.References, r)
			}
		}
		vulns = append(vulns, vuln)
	}

	// Handle --latest flag
	if *latest > 0 {
		sort.Slice(vulns, func(i, j int) bool {
			return vulns[i].Dates.Entry > vulns[j].Dates.Entry
		})

		fmt.Println("Latest Vulnerabilities:")
		for i := 0; i < *latest && i < len(vulns); i++ {
			vuln := vulns[i]
			fmt.Printf("%s  %s\n", vuln.Dates.Entry, vuln.Topic)
		}
		os.Exit(0)
	}

	vulnMap := make(map[string]Vuln)
	for _, v := range vulns {
		vulnMap[v.Vid] = v
	}

	foundCount := 0
	// Use a map to keep track of printed VIDs to avoid duplicates
	printedVids := make(map[string]bool)

	// 6. Perform searches based on flags
	if *id != "" {
		if vuln, ok := vulnMap[*id]; ok {
			if !printedVids[vuln.Vid] {
				printVuln(vuln, *showDesc)
				foundCount++
				printedVids[vuln.Vid] = true
			}
		}
	} else if *topic != "" {
		re, err := regexp.Compile(*topic)
		if err != nil {
			log.Fatalf("Invalid regex for topic: %v", err)
		}
		for _, vuln := range vulnMap {
			if re.MatchString(vuln.Topic) {
				if !printedVids[vuln.Vid] {
					printVuln(vuln, *showDesc)
					foundCount++
					printedVids[vuln.Vid] = true
				}
			}
		}
	} else if *keyword != "" {
		re, err := regexp.Compile(*keyword)
		if err != nil {
			log.Fatalf("Invalid regex for keyword: %v", err)
		}
		for _, vuln := range vulnMap {
			if re.MatchString(vuln.Topic) || re.MatchString(vuln.Description) {
				if !printedVids[vuln.Vid] {
					printVuln(vuln, *showDesc)
					foundCount++
					printedVids[vuln.Vid] = true
				}
			}
		}
	} else if *pkg != "" {
		parts := strings.SplitN(*pkg, "~", 2)
		pkgName := parts[0]
		var pkgVersion string
		if len(parts) > 1 {
			pkgVersion = parts[1]
		}

		for _, vuln := range vulnMap {
			for _, affectedPkg := range vuln.Affects {
				match := false
				if *reNames {
					if re, err := regexp.Compile(pkgName); err == nil && re.MatchString(affectedPkg.Name) {
						match = true
					}
				} else {
					if pkgName == affectedPkg.Name {
						match = true
					}
				}

				if match {
					if pkgVersion == "" {
						if !printedVids[vuln.Vid] {
							printVuln(vuln, *showDesc)
							foundCount++
							printedVids[vuln.Vid] = true
						}
					} else {
						v, err := version.NewVersion(cleanVersion(pkgVersion))
						if err != nil {
							log.Printf("Warning: Invalid package version '%s'. Skipping.", pkgVersion)
							continue
						}

						for _, r := range affectedPkg.Range {
							var constraintStrings []string
							if r.Lt != "" {
								constraintStrings = append(constraintStrings, "< "+cleanVersion(r.Lt))
							}
							if r.Le != "" {
								constraintStrings = append(constraintStrings, "<= "+cleanVersion(r.Le))
							}
							if r.Eq != "" {
								constraintStrings = append(constraintStrings, "= "+cleanVersion(r.Eq))
							}
							if r.Ge != "" {
								constraintStrings = append(constraintStrings, ">= "+cleanVersion(r.Ge))
							}
							if r.Gt != "" {
								constraintStrings = append(constraintStrings, "> "+cleanVersion(r.Gt))
							}
							constraints, err := version.NewConstraint(strings.Join(constraintStrings, ", "))
							if err != nil {
								log.Printf("Warning: Invalid version constraint in vuln %s for package %s. Skipping.", vuln.Vid, affectedPkg.Name)
								continue
							}
							if constraints.Check(v) {
								if !printedVids[vuln.Vid] {
									printVuln(vuln, *showDesc)
									foundCount++
									printedVids[vuln.Vid] = true
								}
							}
						}
					}
				}
			}
		}
	} else if *ref != "" {
		parts := strings.SplitN(*ref, "~", 2)
		source := parts[0]
		var id string
		if len(parts) > 1 {
			id = parts[1]
		}
		for _, vuln := range vulnMap {
			for _, reference := range vuln.References {
				if (source == "" || source == reference.Source) && (id == "" || id == reference.Value) {
					if !printedVids[vuln.Vid] {
						printVuln(vuln, *showDesc)
						foundCount++
						printedVids[vuln.Vid] = true
					}
				}
			}
		}
	} else if *discovery != "" {
		if !isValidDate(*discovery) {
			log.Fatalf("Invalid discovery date format: %s", *discovery)
		}
		for _, vuln := range vulnMap {
			if strings.HasPrefix(vuln.Dates.Discovery, *discovery) {
				if !printedVids[vuln.Vid] {
					printVuln(vuln, *showDesc)
					foundCount++
					printedVids[vuln.Vid] = true
				}
			}
		}
	} else if *entry != "" {
		if !isValidDate(*entry) {
			log.Fatalf("Invalid entry date format: %s", *entry)
		}
		for _, vuln := range vulnMap {
			if strings.HasPrefix(vuln.Dates.Entry, *entry) {
				if !printedVids[vuln.Vid] {
					printVuln(vuln, *showDesc)
					foundCount++
					printedVids[vuln.Vid] = true
				}
			}
		}
	} else if *modified != "" {
		if !isValidDate(*modified) {
			log.Fatalf("Invalid modified date format: %s", *modified)
		}
		for _, vuln := range vulnMap {
			if strings.HasPrefix(vuln.Dates.Modified, *modified) {
				if !printedVids[vuln.Vid] {
					printVuln(vuln, *showDesc)
					foundCount++
					printedVids[vuln.Vid] = true
				}
			}
		}
	} else if *listSources {
		sources := make(map[string]bool)
		for _, vuln := range vulnMap {
			for _, reference := range vuln.References {
				sources[reference.Source] = true
			}
		}
		fmt.Println("References sources:")
		for source := range sources {
			fmt.Printf("  %s\n", source)
		}
	}

	if foundCount > 0 {
		if foundCount == 1 {
			fmt.Println("1 vulnerability found")
		} else {
			fmt.Printf("%d vulnerabilities found\n", foundCount)
		}
	}
}

