#!/bin/sh

set -e

CHECKOUTDIR=./.cache/swagger-ui

mkdir -p $CHECKOUTDIR

if [ ! -d $CHECKOUTDIR/.git ]; then
    git clone https://github.com/swagger-api/swagger-ui.git $CHECKOUTDIR
fi

pushd $CHECKOUTDIR
git checkout master
git fetch --all --tags --prune --force
LATESTTAG=$(git describe --tags $(git rev-list --tags --max-count=1))
echo $LATESTTAG
git branch -D $LATESTTAG || true
git checkout tags/$LATESTTAG -b $LATESTTAG
git reset --hard
echo $(git rev-parse HEAD) > ./dist/REVISION
popd

rm -rf ./resources/swagger-ui/
cp -R $CHECKOUTDIR/dist ./resources/swagger-ui
cp $CHECKOUTDIR/LICENSE ./resources/swagger-ui/

# Replace URL for JSON file.
#NOTE this seems to be macOS quirk (the need for '--')
sed -i -- 's/https:\/\/petstore\.swagger\.io\/v2\/swagger\.json/\.\.\/apidocs\.json/g' './resources/swagger-ui/index.html'
rm './resources/swagger-ui/index.html--'
