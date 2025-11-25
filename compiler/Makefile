all:
	go build c5.go format_tl2go.go 
	./c5 > generated.go
	go run -mod=mod generated.go 
