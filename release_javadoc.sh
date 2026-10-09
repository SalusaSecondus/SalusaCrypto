#!/bin/bash

set -eux

./gradlew javadoc
cd ./lib/build/docs/javadoc/
git init
git remote add javadoc git@github.com:SalusaSecondus/SalusaCrypto.git
git fetch --depth=1 javadoc gh-pages
git add --all
git commit -m 'Javadoc Release'
git merge --allow-unrelated-histories --no-edit -s ours remotes/javadoc/gh-pages
git push javadoc main:gh-pages