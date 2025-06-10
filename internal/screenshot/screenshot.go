package screenshot

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"strconv"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/network"
)

type ScreenshotOptions struct {
	URL             string
	FullPage        bool
	Headers         map[string]interface{}
	Proxy           string
	ChromePath      string
	ThumbnailSize   string
	ScreenshotDelay int
	Timeout         int
}

func TakeScreenshot(opts ScreenshotOptions) ([]byte, error) {
	var pic []byte

	width := 1920
	height := 1080
	if opts.ThumbnailSize != "" {
		size := strings.Split(opts.ThumbnailSize, ",")
		if len(size) == 2 {
			width, _ = strconv.Atoi(size[0])
			height, _ = strconv.Atoi(size[1])
		}
	}

	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Millisecond)
	defer cancelTimeout()

	allocatorOptions := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(width, height),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"),
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("ignore-certificate-errors", true),
	)

	if opts.ChromePath != "" {
		allocatorOptions = append(allocatorOptions, chromedp.ExecPath(opts.ChromePath))
	}
	if opts.Proxy != "" {
		allocatorOptions = append(allocatorOptions, chromedp.ProxyServer(opts.Proxy))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctxTimeout, allocatorOptions...)
	defer cancelAlloc()

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	defer cancelCtx()

	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		err = chromedp.Run(ctx, buildTasks(opts, &pic))
		if err == nil {
			break
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}

	return pic, err
}

func buildTasks(opts ScreenshotOptions, pic *[]byte) chromedp.Tasks {
	headers := network.Headers{}
	for k, v := range opts.Headers {
		headers[k] = v
	}

	tasks := chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(headers),
		chromedp.Navigate(opts.URL),

		// Attempt to bypass TLS warning interstitial
		chromedp.ActionFunc(func(ctx context.Context) error {
			expr := `(() => {
				let clicked = false;
				const adv = document.getElementById('details-button');
				if (adv) {
					adv.click();
					clicked = true;
				}
				const proceed = document.getElementById('proceed-link');
				if (proceed) {
					proceed.click();
					clicked = true;
				}
				return clicked;
			})()`

			res, exp, err := runtime.Evaluate(expr).Do(ctx)
			if err != nil {
				fmt.Println("[screenshot] JS error attempting TLS bypass:", err)
				return nil
			}
			if exp != nil {
				fmt.Println("[screenshot] JS exception attempting TLS bypass:", exp)
				return nil
			}
			if res.Type == "boolean" && res.Value != nil {
				valBytes, err := json.Marshal(res.Value)
				if err == nil {
					var bypassed bool
					if err := json.Unmarshal(valBytes, &bypassed); err == nil && bypassed {
						fmt.Println("[screenshot] TLS bypass triggered successfully")
					} else {
						fmt.Println("[screenshot] No interstitial bypass occurred (elements not found)")
					}
				}
			}
			return nil
		}),

		chromedp.Sleep(1 * time.Second), // Let the bypass finish

		chromedp.WaitReady("body", chromedp.ByQuery), // Wait for actual page

		chromedp.Sleep(time.Duration(opts.ScreenshotDelay) * time.Millisecond), // Delay before screenshot
	}

	if opts.FullPage {
		tasks = append(tasks, chromedp.FullScreenshot(pic, 100))
	} else {
		tasks = append(tasks, chromedp.CaptureScreenshot(pic))
	}

	return tasks
}

