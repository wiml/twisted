#!/bin/bash
set -e
set -x

#
# Initialize the virtualenv if one was created at install time.
#
if [ -f ~/.venv/bin/activate ]; then
    source ~/.venv/bin/activate
fi

tox -- $TOX_FLAGS
