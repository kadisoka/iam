#!/bin/sh

CHECKOUTDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')
TARGETDIR=./iam-server/resources/iam-webui

# We are looking for prereleases here
curl -s https://api.github.com/repos/kadisoka/iam-webui/releases \
| grep -m 1 "browser_download_url.*-iam-webui-.*\.zip" \
| cut -d ":" -f 2,3 \
| awk '{print "--url "$1}' \
| curl -L -o $CHECKOUTDIR/iam-webui.zip --config -

unzip -d $CHECKOUTDIR $CHECKOUTDIR/iam-webui.zip > /dev/null
rm -rf $TARGETDIR
cp -r $CHECKOUTDIR/kadisoka-iam-webui $TARGETDIR
