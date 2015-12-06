#!/bin/sh

mvn -f ../pom.xml -P test-coverage -DrepoToken=$REPO_TOKEN  clean package coveralls:report
