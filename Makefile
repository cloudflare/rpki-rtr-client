
PYTHON = python
PYLINT = pylint

EMAIL = "mahtin@mahtin.com"
NAME = "rpki-rtr-client"

all:	README.rst build

FORCE:

build: setup.py
	$(PYTHON) setup.py -q build

install: build
	sudo $(PYTHON) setup.py -q install
	sudo rm -rf ${NAME}.egg-info

test: all
#	 to be done

sdist: all
	make clean
	make test
	$(PYTHON) setup.py -q sdist
	@rm -rf ${NAME}.egg-info

bdist: all
	make clean
	make test
	$(PYTHON) setup.py -q bdist
	@rm -rf ${NAME}.egg-info

upload: clean all upload-pypi upload-github

upload-pypi:
	$(PYTHON) setup.py -q sdist upload --sign --identity="$(EMAIL)"

upload-github:
	git push

lint:
	$(PYLINT) rtr_client

clean:
	rm -rf build
	rm -rf dist
	mkdir build dist
	$(PYTHON) setup.py -q clean
	rm -rf ${NAME}.egg-info

