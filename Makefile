.PHONY: run
run:
	go run cmd/*.go

.PHONY: clean
clean:
	rm bls

.PHONY: binary
binary:
	go build -o bls cmd/*.go
	ls -al bls

.PHONY: test
test:
	@./test.sh
