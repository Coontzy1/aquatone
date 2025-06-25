package agents

import (
	"context"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/coontzy1/aquatone/core"
	"golang.org/x/sync/semaphore"
)

// ScreenshotOptions defines parameters for taking a screenshot.
type ScreenshotOptions struct {
	URL           string
	FullPage      bool
	Headers       map[string]interface{}
	Proxy         string
	ChromePath    string
	ThumbnailSize string
	DelayMillis   int
	TimeoutMillis int
}

// TakeScreenshot navigates to a URL and captures a screenshot based on options.
func TakeScreenshot(opts ScreenshotOptions) ([]byte, error) {
	var img []byte
	// Parse thumbnail size
	width, height := 1920, 1080
	if opts.ThumbnailSize != "" {
		parts := strings.Split(opts.ThumbnailSize, ",")
		if len(parts) == 2 {
			if w, err := strconv.Atoi(parts[0]); err == nil {
				width = w
			}
			if h, err := strconv.Atoi(parts[1]); err == nil {
				height = h
			}
		}
	}

	// Create contexts
	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Duration(opts.TimeoutMillis)*time.Millisecond)
	defer cancel()

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(width, height),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
			"(KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"),
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("ignore-certificate-errors", true),
	)
	if opts.ChromePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(opts.ChromePath))
	}
	if opts.Proxy != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(opts.Proxy))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctxTimeout, allocOpts...)
	defer cancelAlloc()

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	defer cancelCtx()

	// Attempt up to 3 times
	var err error
	for i := 0; i < 3; i++ {
		err = chromedp.Run(ctx, buildTasks(opts, &img))
		if err == nil {
			break
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return img, err
}

// buildTasks constructs chromedp.Tasks for navigation and screenshot.
func buildTasks(opts ScreenshotOptions, img *[]byte) chromedp.Tasks {
	hdrs := network.Headers{}
	for k, v := range opts.Headers {
		hdrs[k] = v
	}

	tasks := chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(hdrs),
		chromedp.Navigate(opts.URL),
		// Bypass TLS interstitial
		chromedp.ActionFunc(func(ctx context.Context) error {
			expr := `(() => {
				let clicked = false;
				[ 'details-button', 'proceed-link' ].forEach(id => {
					const el = document.getElementById(id);
					if (el) { el.click(); clicked = true }
				});
				return clicked;
			})()`
			_, _, _ = runtime.Evaluate(expr).Do(ctx)
			return nil
		}),
		chromedp.Sleep(1 * time.Second),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(time.Duration(opts.DelayMillis) * time.Millisecond),
	}

	if opts.FullPage {
		tasks = append(tasks, chromedp.FullScreenshot(img, 100))
	} else {
		tasks = append(tasks, chromedp.CaptureScreenshot(img))
	}

	return tasks
}

// URLScreenshotter is an agent that captures screenshots of responsive URLs.
type URLScreenshotter struct {
	session *core.Session
	sem     *semaphore.Weighted // limit concurrency
}

// NewURLScreenshotter creates a new instance of URLScreenshotter.
func NewURLScreenshotter() *URLScreenshotter {
	return &URLScreenshotter{
		sem: semaphore.NewWeighted(8), // limit to 8 concurrent screenshots
	}
}

// ID returns the agent identifier.
func (u *URLScreenshotter) ID() string {
	return "agent:url_screenshotter"
}

// Register subscribes to session events.
func (u *URLScreenshotter) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, u.onURL, false)
	u.session = s
	return nil
}

// onURL handles a new responsive URL notification.
func (u *URLScreenshotter) onURL(raw string) {
	u.session.Out.Debug("[%s] Received URL %s\n", u.ID(), raw)
	page := u.session.GetPage(raw)
	if page == nil {
		u.session.Out.Error("Unable to find page for URL: %s\n", raw)
		return
	}
	u.session.WaitGroup.Add()
	go func(p *core.Page) {
		defer u.session.WaitGroup.Done()
		u.screenshotPage(p)
	}(page)
}

// screenshotPage captures and writes a screenshot for a page.
func (u *URLScreenshotter) screenshotPage(p *core.Page) {
	u.session.Out.Debug("[DEBUG] Attempting to acquire screenshot semaphore for %s\n", p.URL)
	if err := u.sem.Acquire(context.Background(), 1); err != nil {
		u.session.Out.Error("Failed to acquire screenshot semaphore: %v\n", err)
		return
	}
	u.session.Out.Debug("[DEBUG] Acquired screenshot semaphore for %s\n", p.URL)
	defer func() {
		u.sem.Release(1)
		u.session.Out.Debug("[DEBUG] Released screenshot semaphore for %s\n", p.URL)
	}()
	file := fmt.Sprintf("screenshots/%s.png", p.BaseFilename())
	headers := map[string]interface{}{}
	for _, h := range u.session.Options.HTTPHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}
	u.session.Out.Debug("[DEBUG] Starting screenshot for %s\n", p.URL)
	opts := ScreenshotOptions{
		URL:           p.URL,
		FullPage:      u.session.Options.FullPage,
		Headers:       headers,
		Proxy:         u.session.Options.Proxy,
		ChromePath:    u.session.Options.ChromePath,
		ThumbnailSize: u.session.Options.ThumbnailSize,
		DelayMillis:   u.session.Options.ScreenshotDelay,
		TimeoutMillis: u.session.Options.ScreenshotTimeout,
	}
	img, err := TakeScreenshot(opts)
	if err != nil {
		u.session.Out.Error("%s - screenshot failed: %v\n", p.URL, err)
		u.session.Stats.IncrementScreenshotFailed()
		return
	}
	if err := ioutil.WriteFile(u.session.GetFilePath(file), img, 0600); err != nil {
		u.session.Out.Error("%s - write failed: %v\n", p.URL, err)
		u.session.Stats.IncrementScreenshotFailed()
		return
	}
	u.session.Out.Info("%s - screenshot successful\n", p.URL)
	u.session.Stats.IncrementScreenshotSuccessful()
	p.ScreenshotPath = file
	p.HasScreenshot = true
}
