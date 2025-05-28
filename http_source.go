package selfupdate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/semver"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// HTTPSource provide a Source that will download the update from a HTTP url.
// It is expecting the signature file to be served at ${URL}.ed25519
type HTTPSource struct {
	client  *http.Client
	baseURL string
}

var _ Source = (*HTTPSource)(nil)

type platform struct {
	OS         string
	Arch       string
	Ext        string
	Executable string
}

type appVersion struct {
	Name        string `json:"name"`
	OS          string `json:"os"`
	DownloadURL string `json:"download_url"`
	Version     string `json:"version"`
}

// for update and signature using the http.Client provided. To help into providing
// cross platform application, the base is actually a Go Template string where the
// following parameter are recognized:
// {{.OS}} will be filled by the runtime OS name
// {{.Arch}} will be filled by the runtime Arch name
// {{.Ext}} will be filled by the executable expected extension for the OS
// As an example the following string `http://localhost/myapp-{{.OS}}-{{.Arch}}{{.Ext}}`
// would fetch on Windows AMD64 the following URL: `http://localhost/myapp-windows-amd64.exe`
// and on Linux AMD64: `http://localhost/myapp-linux-amd64`.
func NewHTTPSource(client *http.Client, base string) Source {
	if client == nil {
		client = http.DefaultClient
	}

	return &HTTPSource{client: client, baseURL: base}
}

// Get will return if it succeed an io.ReaderCloser to the new executable being downloaded and its length
func (h *HTTPSource) Get(v *Version) (io.ReadCloser, int64, error) {
	var request *http.Request
	var err error
	var response *http.Response

	request, err = http.NewRequest("GET", h.baseURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("error creating request: %s", err)
	}
	response, err = h.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("error downloading %s: %s", h.baseURL, err)
	}
	return response.Body, response.ContentLength, nil
}

func compare(curVersion, newVersion string) (bool, error) {
	curVersion = strings.TrimSpace(curVersion)
	newVersion = strings.TrimSpace(newVersion)
	curSemVer, err := semver.NewVersion(curVersion)
	if err != nil {
		return false, fmt.Errorf("Error parsing current version %s: %s", curVersion, err)
	}
	newSemVer, err := semver.NewVersion(newVersion)
	if err != nil {
		return false, fmt.Errorf("Error parsing new version %s: %s", newVersion, err)
	}
	return curSemVer.LessThan(newSemVer), nil
}

// GetSignature will return the content of  ${URL}.ed25519
func (h *HTTPSource) GetSignature() ([64]byte, error) {
	resp, err := h.client.Get(h.baseURL + ".ed25519")
	if err != nil {
		return [64]byte{}, err
	}
	defer resp.Body.Close()

	if resp.ContentLength != 64 {
		return [64]byte{}, fmt.Errorf("ed25519 signature must be 64 bytes long and was %v", resp.ContentLength)
	}

	writer := bytes.NewBuffer(make([]byte, 0, 64))
	n, err := io.Copy(writer, resp.Body)
	if err != nil {
		return [64]byte{}, err
	}

	if n != 64 {
		return [64]byte{}, fmt.Errorf("ed25519 signature must be 64 bytes long and was %v", n)
	}

	r := [64]byte{}
	copy(r[:], writer.Bytes())

	return r, nil
}

// LatestVersion will return the URL Last-Modified time
func (h *HTTPSource) LatestVersion() (*Version, error) {
	request, err := http.NewRequest("GET", h.baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %s", err)
	}

	response, err := h.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error send request %s: %s", h.baseURL, err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %s", err)
	}
	defer response.Body.Close()
	var appVersions []appVersion
	err = json.Unmarshal(body, &appVersions)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response body: %s", err)
	}

	for _, a := range appVersions {
		if a.OS == runtime.GOOS {
			h.baseURL = a.DownloadURL
			return &Version{Number: a.Version}, nil
		}
	}
	return nil, fmt.Errorf("no version found")
}

func replaceURLTemplate(base string) string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	p := platform{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
		Ext:  ext,
	}

	exe, err := ExecutableRealPath()
	if err != nil {
		exe = filepath.Base(os.Args[0])
	} else {
		exe = filepath.Base(exe)
	}
	if runtime.GOOS == "windows" {
		p.Executable = exe[:len(exe)-len(".exe")]
	} else {
		p.Executable = exe
	}

	t, err := template.New("platform").Parse(base)
	if err != nil {
		return base
	}

	buf := &strings.Builder{}
	err = t.Execute(buf, p)
	if err != nil {
		return base
	}
	return buf.String()
}
