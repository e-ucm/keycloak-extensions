#!/usr/bin/env bash
set -eo pipefail
[[ "${DEBUG}" == "true" ]] && set -x

: ${MAVEN_BUILDER_IMAGE:=maven:3.9.9-eclipse-temurin-17}
: ${KEYCLOAK_VERSION:=24.0.2}

SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  SCRIPT_DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$SCRIPT_DIR/$SOURCE # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SCRIPT_DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )

function usage ()
{
    echo 1>&2 "Usage: ${SOURCE} [Options] [<extension path>]"
    echo 1>&2 "Build keycloak (${KEYCLOAK_VERSION}) extension."
    echo 1>&2 "Options:"
    echo 1>&2 "  -h, --help"
    echo 1>&2 "      Shows this help message and exits."
    echo 1>&2 "  -c, --cache <cache path>"
    echo 1>&2 "      Folder were maven cache is stored (useful to reuse between executions)."
    echo 1>&2 "  -k, --keycloak <keycloak version>"
    echo 1>&2 "      Keycloak version to compile the extension."
}


LIST_LONG_OPTIONS=(
  "help"
  "cache:"
  "keycloak:"
)
LIST_SHORT_OPTIONS=(
  "h"
  "c:"
  "k:"
)

opts=$(getopt \
    --longoptions "$(printf "%s," "${LIST_LONG_OPTIONS[@]}")" \
    --options "$(printf "%s", "${LIST_SHORT_OPTIONS[@]}")" \
    --name "${SOURCE}" \
    -- "$@"
)

eval set -- $opts

extension=""
m2_cache="$(dirname "${SCRIPT_DIR}")/data"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c | --cache )
        m2_cache="$2"
        shift 2
        ;;
    -k | --keycloak )
        KEYCLOAK_VERSION="$2"
        shift 2
        ;;
    --)
      shift
      break
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

extension=$(realpath "$1")

if [[ ! -d "${m2_cache}" ]]; then
    mkdir -p "${m2_cache}"
fi

mvn_cmd="mvn -Duser.home=/maven-config "-Dkeycloak.version=${KEYCLOAK_VERSION}" clean package"
user_uid=$(id -u ${USER})
user_gid=$(id -g ${USER})

docker run --rm --name maven-project-builder \
    -v ${extension}:/usr/src/mymaven \
    -v ${m2_cache}:/maven-config \
    -u ${user_uid}:${user_gid} \
    -w /usr/src/mymaven \
    -e MAVEN_CONFIG=/maven-config/.m2 \
    ${MAVEN_BUILDER_IMAGE} ${mvn_cmd}