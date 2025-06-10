package agents

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/coontzy1/aquatone/core"
	"github.com/coontzy1/aquatone/internal/screenshot"
)

type URLScreenshotter struct {
	session    *core.Session
	chromePath string
}

func NewURLScreenshotter() *URLScreenshotter {
	return &URLScreenshotter{}
}

func (a *URLScreenshotter) ID() string {
	return "agent:url_screenshotter"
}

func (a *URLScreenshotter) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, a.OnURLResponsive, false)
	a.session = s
	return nil
}

func (a *URLScreenshotter) OnURLResponsive(url string) {
	a.session.Out.Debug("[%s] Received new responsive URL %s\n", a.ID(), url)
	page := a.session.GetPage(url)
	if page == nil {
		a.session.Out.Error("Unable to find page for URL: %s\n", url)
		return
	}

	a.session.WaitGroup.Add()
	go func(page *core.Page) {
		defer a.session.WaitGroup.Done()
		a.screenshotPage(page)
	}(page)
}

func (a *URLScreenshotter) screenshotPage(p *core.Page) {
	filePath := fmt.Sprintf("screenshots/%s.png", p.BaseFilename())

	headers := make(map[string]interface{})
	for _, h := range a.session.Options.HTTPHeaders {
		header := strings.SplitN(h, ":", 2)
		if len(header) > 1 {
			headers[header[0]] = header[1]
		}
	}

	opts := screenshot.ScreenshotOptions{
		URL:             p.URL,
		FullPage:        a.session.Options.FullPage,
		Headers:         headers,
		Proxy:           a.session.Options.Proxy,
		ChromePath:      a.session.Options.ChromePath,
		ThumbnailSize:   a.session.Options.ThumbnailSize,
		ScreenshotDelay: a.session.Options.ScreenshotDelay,
		Timeout:         a.session.Options.ScreenshotTimeout,
	}

	pic, err := screenshot.TakeScreenshot(opts)
	if err != nil {
		a.session.Out.Debug("[%s] Screenshot failed for %s: %v\n", a.ID(), p.URL, err)
		a.session.Stats.IncrementScreenshotFailed()
		a.session.Out.Error("%s - %s\n", p.URL, Red("screenshot failed"))
		return
	}

	if err := ioutil.WriteFile(a.session.GetFilePath(filePath), pic, 0700); err != nil {
		a.session.Out.Debug("[%s] Screenshot write failed for %s: %v\n", a.ID(), p.URL, err)
		a.session.Stats.IncrementScreenshotFailed()
		a.session.Out.Error("%s - %s\n", p.URL, Red("screenshot failed"))
		return
	}

	a.session.Out.Debug("[%s] Screenshotted successfully for %s\n", a.ID(), p.URL)
	a.session.Stats.IncrementScreenshotSuccessful()
	a.session.Out.Info("%s - %s\n", p.URL, Green("screenshot successful"))
	p.ScreenshotPath = filePath
	p.HasScreenshot = true
}

