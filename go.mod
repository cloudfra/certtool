module github.com/cloudfra/certtool

go 1.26.2

require (
	filippo.io/age v1.3.2
	filippo.io/hpke v0.4.0
	filippo.io/nistec v0.0.4
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/google/go-cmp v0.7.0
	go.uber.org/zap v1.28.0
	go.uber.org/zap/exp v0.3.0
	golang.org/x/crypto v0.58.0
	gopkg.in/yaml.v3 v3.0.1
	software.sslmate.com/src/go-pkcs12 v0.7.4
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/term v0.47.0 // indirect
)

ignore (
	./build
	./third_party
)
