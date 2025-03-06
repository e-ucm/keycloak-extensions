#!/usr/bin/env bash
set -eo pipefail
[[ "${DEBUG}" == "true" ]] && set -x

: ${BUILD_VERSION:=0.29}

SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  SCRIPT_DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$SCRIPT_DIR/$SOURCE # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SCRIPT_DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )

function usage ()
{
    echo 1>&2 "Usage: ${SOURCE} [Options]"
    echo 1>&2 "Build keycloak event extension (v${BUILD_VERSION})."
    echo 1>&2 "Options:"
    echo 1>&2 "  -h, --help"
    echo 1>&2 "      Shows this help message and exits."
    echo 1>&2 "  -b, --build <build version>"
    echo 1>&2 "      Build version to compile the extension."
}

LIST_LONG_OPTIONS=(
  "help"
  "build:"
)
LIST_SHORT_OPTIONS=(
  "h"
  "b:"
)

opts=$(getopt \
    --longoptions "$(printf "%s," "${LIST_LONG_OPTIONS[@]}")" \
    --options "$(printf "%s", "${LIST_SHORT_OPTIONS[@]}")" \
    --name "${SOURCE}" \
    -- "$@"
)

eval set -- $opts
m2_cache="$(dirname "${SCRIPT_DIR}")/data"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -b | --build )
        BUILD_VERSION="$2"
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

if [[ ! -d "${m2_cache}" ]]; then
    mkdir -p "${m2_cache}"
fi

if [[ -d "./build-keycloak-events-$BUILD_VERSION" ]]; then 
  rm -rf "./build-keycloak-events-$BUILD_VERSION"
fi
mkdir "./build-keycloak-events-$BUILD_VERSION"

echo $BUILD_VERSION
# Checkout code in temp dir
tmp_dir=$(mktemp -d)
ls -lia $tmp_dir
git clone --depth 1 --branch v${BUILD_VERSION} "https://github.com/e-ucm/keycloak-events.git" ${tmp_dir};
chmod -R 777 $tmp_dir
docker run --rm --name maven-project-builder \
    -v $tmp_dir:/usr/src/mymaven -w /usr/src/mymaven \
    -v ${m2_cache}:/usr/src/mymaven/.m2 \
    -u $(id -u ${USER}):$(id -g ${USER}) \
    -e MAVEN_CONFIG=/usr/src/mymaven/.m2 \
    maven:3.9.9-amazoncorretto-23-debian sh -c "apt update && apt install -y git && mvn -Duser.home=/usr/src/mymaven clean package"
cp ${tmp_dir}/target/keycloak-events-$BUILD_VERSION.jar ./build-keycloak-events-$BUILD_VERSION/io.phasetwo.keycloak.keycloak-events-$BUILD_VERSION.jar

pushd "$SCRIPT_DIR/build-keycloak-events-$BUILD_VERSION/"
sha256sum ./* > "$SCRIPT_DIR/build-keycloak-events-$BUILD_VERSION/SHA256SUMS"
popd
rm -rf $tmp_dir