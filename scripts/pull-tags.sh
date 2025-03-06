#!/usr/bin/env bash
set -eo pipefail
[[ "${DEBUG}" == "true" ]] && set -x

#to get new tags from git in our forked repo keycloak events
pushd "../../keycloak-events"
git fetch --tags upstream
git push --tags
popd