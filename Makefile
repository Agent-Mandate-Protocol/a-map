.PHONY: install test build lint clean

install:
	pnpm install

test:
	pnpm test
	cd sdks/python && python -m pytest || true

build:
	pnpm build

lint:
	pnpm lint

clean:
	pnpm clean

test-js:
	pnpm test

test-python:
	cd sdks/python && python -m pytest
