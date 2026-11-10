.PHONY: all build sync-extension validate simulate-research stats test

all: build simulate-research sync-extension validate test

build:
	python3 cli.py build

sync-extension:
	python3 cli.py sync

validate:
	python3 cli.py validate

simulate-research:
	python3 cli.py simulate-research

stats:
	python3 cli.py stats

test:
	python3 -m unittest discover -s tests -p "test_*.py" -v
