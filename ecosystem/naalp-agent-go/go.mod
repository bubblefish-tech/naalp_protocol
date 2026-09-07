module github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go

go 1.25.0

require (
	github.com/bubblefish-tech/naalp_protocol/impl/go v0.0.0-00010101000000-000000000000
	github.com/cloudflare/circl v1.6.4
)

require (
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

// Dev-local replace: this ecosystem module is an in-repo sibling of the Part-1 reference
// SDK, never a published dependency of it (design.md "Buy-before-make" -- this module
// wraps impl/go's existing exports and adds no primitive of its own).
replace github.com/bubblefish-tech/naalp_protocol/impl/go => ../../impl/go
