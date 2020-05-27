#!/bin/sh
test -e ./ConnArtist.py || { echo "Missing ConnArtist, wrong dir?" >&2; exit 1;}

test -d flaskVENV || ./createVirtualEnvironment.sh || exit 2

echo "$PS1" | grep -q '(flaskVENV)' || . flaskVENV/bin/activate
echo "$PS1" | grep -q '(flaskVENV)' || { echo "fail venv" >&2; exit 3;}

flask --version 2>&1 >/dev/null || pip install flask

FLASK_APP=ConnArtist.py flask run
