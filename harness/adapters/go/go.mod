module github.com/bubblefish-tech/naalp_protocol/harness/adapters/go

go 1.24.0

require (
	github.com/bubblefish-tech/naalp_protocol/impl/go v0.0.0
	github.com/cloudflare/circl v1.6.4
)

require golang.org/x/sys v0.38.0 // indirect

require golang.org/x/text v0.21.0 // indirect

replace github.com/bubblefish-tech/naalp_protocol/impl/go => ../../../impl/go
