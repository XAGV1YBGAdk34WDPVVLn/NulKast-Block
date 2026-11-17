.PHONY: all build sync-extension package-store validate simulate-research stats test

all: build simulate-research sync-extension package-store validate test

build:
	python3 cli.py build

sync-extension:
	python3 cli.py sync

package-store:
	python3 cli.py package-store

validate:
	python3 cli.py validate

simulate-research:
	python3 cli.py simulate-research

stats:
	python3 cli.py stats

test:
	python3 -m unittest discover -s tests -p "test_*.py" -v
