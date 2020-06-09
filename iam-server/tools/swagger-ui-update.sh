#!/bin/sh

set -e

CHECKOUTDIR=./.cache/swagger-ui
TARGETDIR=./iam-server/resources/swagger-ui

rm -rf $CHECKOUTDIR
mkdir -p $CHECKOUTDIR

# https://stackoverflow.com/questions/10649814/get-last-git-tag-from-a-remote-repo-without-cloning
LATESTTAG=$(git ls-remote --tags --refs --sort="v:refname" https://github.com/swagger-api/swagger-ui.git | tail -n1 | sed 's/.*\///')
echo "Version $LATESTTAG"

git -c advice.detachedHead=false clone --depth 1 --branch $LATESTTAG https://github.com/swagger-api/swagger-ui.git $CHECKOUTDIR

echo $LATESTTAG > $CHECKOUTDIR/dist/VERSION
echo $(git --git-dir=$CHECKOUTDIR/.git rev-parse HEAD) >> $CHECKOUTDIR/dist/VERSION

echo "Copying files..."
rm -rf $TARGETDIR/
cp -r $CHECKOUTDIR/dist $TARGETDIR
cp $CHECKOUTDIR/LICENSE $TARGETDIR/

# Replace URL for JSON file.
#NOTE this seems to be macOS quirk (the need for '--')
sed -i -- 's/https:\/\/petstore\.swagger\.io\/v2\/swagger\.json/\.\.\/apidocs\.json/g' "$TARGETDIR/index.html"
rm "$TARGETDIR/index.html--"

echo "Done."
