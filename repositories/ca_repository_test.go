package repositories_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/pivotal-cf/cm-cli/repositories"

	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/pivotal-cf/cm-cli/client/clientfakes"
	"github.com/pivotal-cf/cm-cli/models"
)

var _ = Describe("CaRepository", func() {
	var (
		repository CaRepository
		httpClient clientfakes.FakeHttpClient
	)

	Describe("SendRequest", func() {
		Context("when there is a response body", func() {
			BeforeEach(func() {
				repository = NewCaRepository(&httpClient)
			})

			It("sends a request to the server", func() {
				request, _ := http.NewRequest("PUT", "http://example.com/foo", nil)

				responseObj := http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(`{"root":{"public":"my-pub","private":"my-priv"}}`))),
				}

				httpClient.DoStub = func(req *http.Request) (resp *http.Response, err error) {
					Expect(req).To(Equal(request))

					return &responseObj, nil
				}

				caParams := models.CaParameters{
					Public:  "my-pub",
					Private: "my-priv",
				}
				expectedCaBody := models.CaBody{
					Ca: &caParams,
				}

				caBody, err := repository.SendRequest(request)

				Expect(err).ToNot(HaveOccurred())
				Expect(caBody).To(Equal(expectedCaBody))
			})
		})
	})
})
