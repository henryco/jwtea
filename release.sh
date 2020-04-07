#!/bin/bash
arg1=$1
TAG=${arg1:="HEAD"}

echo "scm.url=scm:git:git://github.com/henryco/jwtea.git" > release.properties
echo "scm.tag=${TAG}" >> release.properties

mvn release:perform