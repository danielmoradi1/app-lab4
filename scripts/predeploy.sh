#!/usr/bin/env bash
set -e
IMAGE=${1:-app-lab4:secure}
SBOM=artifacts/sbom.json
TRIVY=artifacts/trivy_secure.json
PUB=cosign.pub

[ -f "$SBOM" ] || { echo "SBOM missing"; exit 1; }

if jq '.Results[].Vulnerabilities[]? | select(.Severity=="HIGH" or .Severity=="CRITICAL")' $TRIVY | grep -q .; then
  echo "CVE policy fail"; exit 2
fi

docker run --rm -v $PWD:/work -w /work cgr.dev/chainguard/cosign verify --key "$PUB" "$IMAGE" > /dev/null 2>&1 || { echo "Cosign verify failed"; exit 3; }

echo "Predeploy checks passed"
