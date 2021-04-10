/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mrunalp/fileutils"

	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	restclient "k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/certificate"
	"k8s.io/client-go/util/keyutil"
)

//create storeCertData of the store which used by bootstrap process. used for TestLoadClientConfig
var storeCertData = newCertificateData(`-----BEGIN CERTIFICATE-----
MIICRzCCAfGgAwIBAgIJALMb7ecMIk3MMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEYMBYGA1UE
CgwPR2xvYmFsIFNlY3VyaXR5MRYwFAYDVQQLDA1JVCBEZXBhcnRtZW50MRswGQYD
VQQDDBJ0ZXN0LWNlcnRpZmljYXRlLTAwIBcNMTcwNDI2MjMyNjUyWhgPMjExNzA0
MDIyMzI2NTJaMH4xCzAJBgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNV
BAcMBkxvbmRvbjEYMBYGA1UECgwPR2xvYmFsIFNlY3VyaXR5MRYwFAYDVQQLDA1J
VCBEZXBhcnRtZW50MRswGQYDVQQDDBJ0ZXN0LWNlcnRpZmljYXRlLTAwXDANBgkq
hkiG9w0BAQEFAANLADBIAkEAtBMa7NWpv3BVlKTCPGO/LEsguKqWHBtKzweMY2CV
tAL1rQm913huhxF9w+ai76KQ3MHK5IVnLJjYYA5MzP2H5QIDAQABo1AwTjAdBgNV
HQ4EFgQU22iy8aWkNSxv0nBxFxerfsvnZVMwHwYDVR0jBBgwFoAU22iy8aWkNSxv
0nBxFxerfsvnZVMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAEOefGbV
NcHxklaW06w6OBYJPwpIhCVozC1qdxGX1dg8VkEKzjOzjgqVD30m59OFmSlBmHsl
nkVA6wyOSDYBf3o=
-----END CERTIFICATE-----`, `-----BEGIN RSA PRIVATE KEY-----
MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAtBMa7NWpv3BVlKTC
PGO/LEsguKqWHBtKzweMY2CVtAL1rQm913huhxF9w+ai76KQ3MHK5IVnLJjYYA5M
zP2H5QIDAQABAkAS9BfXab3OKpK3bIgNNyp+DQJKrZnTJ4Q+OjsqkpXvNltPJosf
G8GsiKu/vAt4HGqI3eU77NvRI+mL4MnHRmXBAiEA3qM4FAtKSRBbcJzPxxLEUSwg
XSCcosCktbkXvpYrS30CIQDPDxgqlwDEJQ0uKuHkZI38/SPWWqfUmkecwlbpXABK
iQIgZX08DA8VfvcA5/Xj1Zjdey9FVY6POLXen6RPiabE97UCICp6eUW7ht+2jjar
e35EltCRCjoejRHTuN9TC0uCoVipAiAXaJIx/Q47vGwiw6Y8KXsNU6y54gTbOSxX
54LzHNk/+Q==
-----END RSA PRIVATE KEY-----`)

type certificateData struct {
	keyPEM         []byte
	certificatePEM []byte
	certificate    *tls.Certificate
}

func newCertificateData(certificatePEM string, keyPEM string) *certificateData {
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(keyPEM))
	if err != nil {
		panic(fmt.Sprintf("Unable to initialize certificate: %v", err))
	}
	certs, err := x509.ParseCertificates(certificate.Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("Unable to initialize certificate leaf: %v", err))
	}
	certificate.Leaf = certs[0]
	return &certificateData{
		keyPEM:         []byte(keyPEM),
		certificatePEM: []byte(certificatePEM),
		certificate:    &certificate,
	}
}

func TestLoadClientConfig(t *testing.T) {
	//Create a temporary folder under tmp to store the required certificate files and configuration files.
	filedir, err := ioutil.TempDir("", "dir-")
	defer os.RemoveAll(filedir)
	fileutils.CopyDirectory("./testdata", filedir)
	testDataValid := []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: ca-a.crt
    server: https://cluster-a.com
  name: cluster-a
- cluster:
    server: https://cluster-b.com
  name: cluster-b
contexts:
- context:
    cluster: cluster-a
    namespace: ns-a
    user: user-a
  name: context-a
- context:
    cluster: cluster-b
    namespace: ns-b
    user: user-b
  name: context-b
current-context: context-b
users:
- name: user-a
  user:
    client-certificate: mycertvalid.crt
    client-key: mycertvalid.key
- name: user-b
  user:
    client-certificate: mycertvalid.crt
    client-key: mycertvalid.key

`)
	fvalid, err := ioutil.TempFile(filedir, "kubeconfigvalid")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(fvalid.Name(), testDataValid, os.FileMode(0755))

	testDataInvalid := []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: ca-a.crt
    server: https://cluster-a.com
  name: cluster-a
- cluster:
    server: https://cluster-b.com
  name: cluster-b
contexts:
- context:
    cluster: cluster-a
    namespace: ns-a
    user: user-a
  name: context-a
- context:
    cluster: cluster-b
    namespace: ns-b
    user: user-b
  name: context-b
current-context: context-b
users:
- name: user-a
  user:
    client-certificate: mycertinvalid.crt
    client-key: mycertinvalid.key
- name: user-b
  user:
    client-certificate: mycertinvalid.crt
    client-key: mycertinvalid.key

`)
	/*	TLSClientConfig:
		      client-certificate:
				args{"testdata/mycertvalid.crt"}.config
			  client-key:
				args{"testdata/mycertvalid.key"}.config
	*/
	finvalid, err := ioutil.TempFile(filedir, "kubeconfiginvalid")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(finvalid.Name(), testDataInvalid, os.FileMode(0755))

	testDatabootstrap := []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: ca-a.crt
    server: https://cluster-a.com
  name: cluster-a
- cluster:
    server: https://cluster-b.com
  name: cluster-b
contexts:
- context:
    cluster: cluster-a
    namespace: ns-a
    user: user-a
  name: context-a
- context:
    cluster: cluster-b
    namespace: ns-b
    user: user-b
  name: context-b
current-context: context-b
users:
- name: user-a
  user:
   token: mytoken-b
- name: user-b
  user:
   token: mytoken-b
`)
	fboot, err := ioutil.TempFile(filedir, "kubeconfig")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(fboot.Name(), testDatabootstrap, os.FileMode(0755))

	dir, err := ioutil.TempDir(filedir, "k8s-test-certstore-current")
	if err != nil {
		t.Fatalf("Unable to create the test directory %q: %v", dir, err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("Unable to clean up test directory %q: %v", dir, err)
		}
	}()
	keyFile := filepath.Join(dir, "kubelet.key")
	if err := ioutil.WriteFile(keyFile, storeCertData.keyPEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", keyFile, err)
	}
	certFile := filepath.Join(dir, "kubelet.crt")
	if err := ioutil.WriteFile(certFile, storeCertData.certificatePEM, 0600); err != nil {
		t.Fatalf("Unable to create the file %q: %v", certFile, err)
	}

	store, err := certificate.NewFileStore("kubelet-client", dir, dir, "", "")
	if err != nil {
		t.Errorf("unable to build bootstrap cert store")
	}

	tests := []struct {
		name                 string
		kubeconfigPath       string
		bootstrapPath        string
		certDir              string
		expectedCertConfig   *restclient.Config
		expectedClientConfig *restclient.Config
	}{
		{
			name:           "bootstrapPath is empty",
			kubeconfigPath: fvalid.Name(),
			bootstrapPath:  "",
			certDir:        dir,
			expectedCertConfig: &restclient.Config{
				Host: "https://cluster-b.com",
				TLSClientConfig: restclient.TLSClientConfig{
					CertFile: filedir + "/mycertvalid.crt",
					KeyFile:  filedir + "/mycertvalid.key",
				},
				BearerToken: "",
			},
			expectedClientConfig: &restclient.Config{
				Host: "https://cluster-b.com",
				TLSClientConfig: restclient.TLSClientConfig{
					CertFile: filedir + "/mycertvalid.crt",
					KeyFile:  filedir + "/mycertvalid.key",
				},
				BearerToken: "",
			},
		},
		{
			name:           "bootstrap path is set and the contents of kubeconfigPath are valid",
			kubeconfigPath: fvalid.Name(),
			bootstrapPath:  fboot.Name(),
			certDir:        dir,
			expectedCertConfig: &restclient.Config{
				Host: "https://cluster-b.com",
				TLSClientConfig: restclient.TLSClientConfig{
					CertFile: filedir + "/mycertvalid.crt",
					KeyFile:  filedir + "/mycertvalid.key",
				},
				BearerToken: "",
			},
			expectedClientConfig: &restclient.Config{
				Host: "https://cluster-b.com",
				TLSClientConfig: restclient.TLSClientConfig{
					CertFile: filedir + "/mycertvalid.crt",
					KeyFile:  filedir + "/mycertvalid.key",
				},
				BearerToken: "",
			},
		},
		{
			name:           "bootstrap path is set and the contents of kubeconfigPath are not valid",
			kubeconfigPath: finvalid.Name(),
			bootstrapPath:  fboot.Name(),
			certDir:        dir,
			expectedCertConfig: &restclient.Config{
				Host:            "https://cluster-b.com",
				TLSClientConfig: restclient.TLSClientConfig{},
				BearerToken:     "mytoken-b",
			},
			expectedClientConfig: &restclient.Config{
				Host: "https://cluster-b.com",
				TLSClientConfig: restclient.TLSClientConfig{
					CertFile: store.CurrentPath(),
					KeyFile:  store.CurrentPath(),
				},
				BearerToken: "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certConfig, clientConfig, err := LoadClientConfig(test.kubeconfigPath, test.bootstrapPath, test.certDir)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(certConfig, test.expectedCertConfig) {
				t.Errorf("Unexpected certConfig: %s", diff.ObjectDiff(certConfig, test.expectedCertConfig))
			}
			if !reflect.DeepEqual(clientConfig, test.expectedClientConfig) {
				t.Errorf("Unexpected clientConfig: %s", diff.ObjectDiff(clientConfig, test.expectedClientConfig))
			}
		})
	}
}

func TestLoadRESTClientConfig(t *testing.T) {
	testData := []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: ca-a.crt
    server: https://cluster-a.com
  name: cluster-a
- cluster:
    certificate-authority-data: VGVzdA==
    server: https://cluster-b.com
  name: cluster-b
contexts:
- context:
    cluster: cluster-a
    namespace: ns-a
    user: user-a
  name: context-a
- context:
    cluster: cluster-b
    namespace: ns-b
    user: user-b
  name: context-b
current-context: context-b
users:
- name: user-a
  user:
    token: mytoken-a
- name: user-b
  user:
    token: mytoken-b
`)
	f, err := ioutil.TempFile("", "kubeconfig")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	ioutil.WriteFile(f.Name(), testData, os.FileMode(0755))

	config, err := loadRESTClientConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	expectedConfig := &restclient.Config{
		Host: "https://cluster-b.com",
		TLSClientConfig: restclient.TLSClientConfig{
			CAData: []byte(`Test`),
		},
		BearerToken: "mytoken-b",
	}

	if !reflect.DeepEqual(config, expectedConfig) {
		t.Errorf("Unexpected config: %s", diff.ObjectDiff(config, expectedConfig))
	}
}

func TestRequestNodeCertificateNoKeyData(t *testing.T) {
	certData, err := requestNodeCertificate(context.TODO(), newClientset(fakeClient{}), []byte{}, "fake-node-name")
	if err == nil {
		t.Errorf("Got no error, wanted error an error because there was an empty private key passed in.")
	}
	if certData != nil {
		t.Errorf("Got cert data, wanted nothing as there should have been an error.")
	}
}

func TestRequestNodeCertificateErrorCreatingCSR(t *testing.T) {
	client := newClientset(fakeClient{
		failureType: createError,
	})
	privateKeyData, err := keyutil.MakeEllipticPrivateKeyPEM()
	if err != nil {
		t.Fatalf("Unable to generate a new private key: %v", err)
	}

	certData, err := requestNodeCertificate(context.TODO(), client, privateKeyData, "fake-node-name")
	if err == nil {
		t.Errorf("Got no error, wanted error an error because client.Create failed.")
	}
	if certData != nil {
		t.Errorf("Got cert data, wanted nothing as there should have been an error.")
	}
}

func TestRequestNodeCertificate(t *testing.T) {
	privateKeyData, err := keyutil.MakeEllipticPrivateKeyPEM()
	if err != nil {
		t.Fatalf("Unable to generate a new private key: %v", err)
	}

	certData, err := requestNodeCertificate(context.TODO(), newClientset(fakeClient{}), privateKeyData, "fake-node-name")
	if err != nil {
		t.Errorf("Got %v, wanted no error.", err)
	}
	if certData == nil {
		t.Errorf("Got nothing, expected a CSR.")
	}
}

type failureType int

const (
	noError failureType = iota
	createError
	certificateSigningRequestDenied
)

type fakeClient struct {
	certificatesclient.CertificateSigningRequestInterface
	failureType failureType
}

func newClientset(opts fakeClient) *fake.Clientset {
	f := fake.NewSimpleClientset()
	switch opts.failureType {
	case createError:
		f.PrependReactor("create", "certificatesigningrequests", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
			switch action.GetResource().Version {
			case "v1":
				return true, nil, fmt.Errorf("create error")
			default:
				return true, nil, apierrors.NewNotFound(certificatesv1.Resource("certificatesigningrequests"), "")
			}
		})
	default:
		f.PrependReactor("create", "certificatesigningrequests", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
			switch action.GetResource().Version {
			case "v1":
				return true, &certificatesv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: "fake-certificate-signing-request-name", UID: "fake-uid"}}, nil
			default:
				return true, nil, apierrors.NewNotFound(certificatesv1.Resource("certificatesigningrequests"), "")
			}
		})
		f.PrependReactor("list", "certificatesigningrequests", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
			switch action.GetResource().Version {
			case "v1":
				return true, &certificatesv1.CertificateSigningRequestList{Items: []certificatesv1.CertificateSigningRequest{{ObjectMeta: metav1.ObjectMeta{Name: "fake-certificate-signing-request-name", UID: "fake-uid"}}}}, nil
			default:
				return true, nil, apierrors.NewNotFound(certificatesv1.Resource("certificatesigningrequests"), "")
			}
		})
		f.PrependWatchReactor("certificatesigningrequests", func(action clienttesting.Action) (handled bool, ret watch.Interface, err error) {
			switch action.GetResource().Version {
			case "v1":
				w := watch.NewFakeWithChanSize(1, false)
				w.Add(opts.generateCSR())
				w.Stop()
				return true, w, nil

			default:
				return true, nil, apierrors.NewNotFound(certificatesv1.Resource("certificatesigningrequests"), "")
			}
		})
	}
	return f
}

func (c fakeClient) generateCSR() runtime.Object {
	var condition certificatesv1.CertificateSigningRequestCondition
	var certificateData []byte
	if c.failureType == certificateSigningRequestDenied {
		condition = certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateDenied,
		}
	} else {
		condition = certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateApproved,
		}
		certificateData = []byte(`issued certificate`)
	}

	csr := certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			UID: "fake-uid",
		},
		Status: certificatesv1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1.CertificateSigningRequestCondition{
				condition,
			},
			Certificate: certificateData,
		},
	}
	return &csr
}
