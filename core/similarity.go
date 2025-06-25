package core

import (
	"fmt"
	"io"

	"github.com/pmezard/go-difflib/difflib"
	"golang.org/x/net/html"
)

func GetPageStructure(body io.Reader) ([]string, error) {
	var structure []string
	z := html.NewTokenizer(body)
	for {
		tt := z.Next()
		token := z.Token()
		switch tt {
		case html.ErrorToken:
			if z.Err() == io.EOF {
				return structure, nil
			}
			return structure, z.Err()
		case html.StartTagToken:
			structure = append(structure, token.Data)
			for _, attr := range token.Attr {
				if attr.Key != "id" {
					continue
				}
				structure = append(structure, fmt.Sprintf("#%s", attr.Val))
				break
			}
		}
	}
}

func GetSimilarity(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0 // Both empty, consider them identical
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0 // One empty, consider them completely different
	}

	matcher := difflib.NewMatcher(a, b)
	return matcher.Ratio()
}
