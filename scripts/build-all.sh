#!/usr/bin/env bash
set -eo pipefail
[[ "${DEBUG}" == "true" ]] && set -x

: ${BUILD_VERSION:=1.1.0}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v | --version )
        BUILD_VERSION="$2"
        shift 2
        ;;
    *)
      usage
      exit 1
      ;;
    esac
done

if [[ -d "./builds" ]]; then 
  rm -rf "./builds"
fi
mkdir "./builds"

./build.sh --keycloak 24.0.2 ../custom-token-auth-spi
cp ../custom-token-auth-spi/target/es.e-ucm.simva.keycloak.custom-token-auth-spi-$BUILD_VERSION.jar ./builds/es.e-ucm.simva.keycloak.custom-token-auth-spi-$BUILD_VERSION.jar  
./build.sh --keycloak 24.0.2 ../fullname-attribute-mapper
cp ../fullname-attribute-mapper/target/es.e-ucm.simva.keycloak.fullname-attribute-mapper-$BUILD_VERSION.jar ./builds/es.e-ucm.simva.keycloak.fullname-attribute-mapper-$BUILD_VERSION.jar  
./build.sh --keycloak 24.0.2 ../policy-attribute-mapper
cp ../policy-attribute-mapper/target/es.e-ucm.simva.keycloak.policy-attribute-mapper-$BUILD_VERSION.jar ./builds/es.e-ucm.simva.keycloak.policy-attribute-mapper-$BUILD_VERSION.jar  
./build.sh --keycloak 24.0.2 ../simva-theme
cp ../simva-theme/target/es.e-ucm.simva.keycloak.simva-theme-$BUILD_VERSION.jar ./builds/es.e-ucm.simva.keycloak.simva-theme-$BUILD_VERSION.jar  
./build.sh --keycloak 10.0.2 ../lti-oidc-mapper
cp ../lti-oidc-mapper/target/es.e-ucm.simva.keycloak.lti-oidc-mapper-$BUILD_VERSION.jar ./builds/es.e-ucm.simva.keycloak.lti-oidc-mapper-$BUILD_VERSION.jar  
./build.sh --keycloak 10.0.2 ../script-policy-attribute-mapper
cp ../script-policy-attribute-mapper/target/es.e-ucm.simva.keycloak.script-policy-attribute-mapper-$BUILD_VERSION.jar ./builds/es.e-ucm.simva.keycloak.script-policy-attribute-mapper-$BUILD_VERSION.jar  
sha256sum ./builds/* > "./builds/SHA256SUMS"