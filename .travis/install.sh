#!/bin/bash
#
# Helper for setting up the test environment on Travis.
#
# If running the tests requires a virtualenv, create it at `~/.venv` as the
# test run step will activate the virtualenv from that location.
#
set -e
set -x

# Version used to run the PYPY tests as defined by pyenv.
export PYPY_VERSION="pypy-5.3.1"


if [[ "$(uname -s)" == 'Darwin' ]]; then
    # On OSX we run the tests in a virtualenv using the default Python version
    # provide by the OS.
    curl -O https://bootstrap.pypa.io/get-pip.py
    python get-pip.py --user
    python -m pip install --user virtualenv
    python -m virtualenv ~/.venv
    source ~/.venv/bin/activate
elif [ "$TRAVIS_PYTHON_VERSION" = "pypy" ]; then
    # PYPY are executed in a virtualenv created using a PYPY version obtained
    # using pyenv.
    export PYENV_ROOT="$HOME/.pyenv"

    if [ -f "$PYENV_ROOT/bin/pyenv" ]; then
        # pyenv already exists. Just updated it.
        pushd "$PYENV_ROOT"
        git pull
        popd
    else
        rm -rf "$PYENV_ROOT"
        git clone --depth 1 https://github.com/yyuu/pyenv.git "$PYENV_ROOT"
    fi

    # Until PYPY coverage fix is released we using pypy-dev which requires
    # Python 2.7.
    # https://bitbucket.org/pypy/pypy/issues/2335
    "$PYENV_ROOT/bin/pyenv" install --skip-existing "$PYPY_VERSION"
    virtualenv --python="$PYENV_ROOT/versions/$PYPY_VERSION/bin/python" ~/.venv
    source ~/.venv/bin/activate
fi

pip install $@
