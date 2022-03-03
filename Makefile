.PHONY: run
run:
	go run cmd/*.go

.PHONY: test
test:
	@./test.sh
