#!/bin/sh
test -e ./ConnArtist.py || { echo "Missing ConnArtist, wrong dir?" >&2; exit 1;}

test -d flaskVENV || ./createVirtualEnvironment.sh || exit 2

if [ $(id -un) != connartist ]; then
 sudo -p "Enter your password to run as connartist: " -u connartist $0
 exit
fi

echo "$PS1" | grep -q '(flaskVENV)' || . flaskVENV/bin/activate
echo "$PS1" | grep -q '(flaskVENV)' || { echo "fail venv" >&2; exit 3;}

flask --version 2>&1 >/dev/null || pip install flask

FLASK_APP=ConnArtist.py flask run --host=0.0.0.0
