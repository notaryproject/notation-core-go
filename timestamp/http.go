// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package timestamp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// maxBodyLength specifies the max content can be received from the possibly malicious
// remote server.
// The legnth of a regular TSA response with certificates is usually less than 10 KiB.
const maxBodyLength = 1 * 1024 * 1024 // 1 MiB

// httpTimestamper is a HTTP-based timestamper.
type httpTimestamper struct {
	rt       http.RoundTripper
	endpoint string
}

// NewHTTPTimestamper creates a HTTP-based timestamper with the endpoint provided by the TSA.
// http.DefaultTransport is used if nil RoundTripper is passed.
func NewHTTPTimestamper(rt http.RoundTripper, endpoint string) (Timestamper, error) {
	if rt == nil {
		rt = http.DefaultTransport
	}
	if _, err := url.Parse(endpoint); err != nil {
		return nil, err
	}
	return &httpTimestamper{
		rt:       rt,
		endpoint: endpoint,
	}, nil
}

// Timestamp sends the request to the remote TSA server for timestamping.
// Reference: RFC 3161 3.4 Time-Stamp Protocol via HTTP
func (ts *httpTimestamper) Timestamp(ctx context.Context, req *Request) (*Response, error) {
	// prepare for http request
	reqBytes, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Content-Type", "application/timestamp-query")

	// send the request to the remote TSA server
	hResp, err := ts.rt.RoundTrip(hReq)
	if err != nil {
		return nil, err
	}
	defer hResp.Body.Close()

	// verify HTTP response
	if hResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %q: https response bad status: %s", http.MethodPost, ts.endpoint, hResp.Status)
	}
	if contentType := hResp.Header.Get("Content-Type"); contentType != "application/timestamp-reply" {
		return nil, fmt.Errorf("%s %q: unexpected response content type: %s", http.MethodPost, ts.endpoint, contentType)
	}

	// read response
	body := io.LimitReader(hResp.Body, maxBodyLength)
	respBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := resp.UnmarshalBinary(respBytes); err != nil {
		return nil, err
	}
	return &resp, nil
}
