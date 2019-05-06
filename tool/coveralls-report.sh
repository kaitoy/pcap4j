#!/bin/sh

./mvnw -e -P test-coverage -DrepoToken=$COVERALLS_REPO_TOKEN  clean verify coveralls:report
