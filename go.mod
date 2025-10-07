module gensecpass

go 1.25

require (
	cme v0.0.0-20220713145830-47cc09abe802
	filippo.io/age v1.2.0
	github.com/awnumar/memguard v0.22.5
	golang.org/x/term v0.25.0
)

require (
	github.com/awnumar/memcall v0.2.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
)

// Fix the broken module path in c-goes/classic-mceliece-go
replace cme => github.com/c-goes/classic-mceliece-go v0.0.0-20220713145830-47cc09abe802
