#!/usr/bin/env bash
set -euo pipefail

image=${1:?usage: smoke-github-app-image.sh IMAGE}
container="foxguard-github-app-smoke-$$"
tmpdir=$(mktemp -d)

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

# These credentials exist only for this local smoke-test container. They never
# leave the runner and cannot authenticate as a real GitHub App.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "${tmpdir}/test-private-key.pem" 2>/dev/null
chmod 0644 "${tmpdir}/test-private-key.pem"

docker run --detach --name "${container}" \
  --publish 127.0.0.1::8080 \
  --mount "type=bind,src=${tmpdir}/test-private-key.pem,dst=/tmp/test-private-key.pem,readonly" \
  --env FOXGUARD_WEBHOOK_SECRET=smoke-test-not-a-secret \
  --env FOXGUARD_GITHUB_APP_ID=1 \
  --env FOXGUARD_GITHUB_PRIVATE_KEY_PATH=/tmp/test-private-key.pem \
  --env FOXGUARD_INSTALLATIONS_PATH=/tmp/installations.json \
  "${image}" >/dev/null

port=$(docker port "${container}" 8080/tcp | sed -n 's/.*://p' | head -n 1)
if [[ -z "${port}" ]]; then
  echo "::error::Docker did not publish the GitHub App health port"
  docker logs "${container}" >&2
  exit 1
fi

for attempt in $(seq 1 30); do
  if [[ "$(docker inspect --format '{{.State.Running}}' "${container}")" != true ]]; then
    echo "::error::GitHub App container exited before becoming healthy"
    docker logs "${container}" >&2
    exit 1
  fi

  if response=$(curl --fail --silent --show-error "http://127.0.0.1:${port}/healthz" 2>/dev/null); then
    if [[ "${response}" != "ok" ]]; then
      echo "::error::GitHub App /healthz returned an unexpected body: ${response}"
      docker logs "${container}" >&2
      exit 1
    fi
    echo "GitHub App container started and /healthz returned 200 with body 'ok'."
    exit 0
  fi
  sleep 1
done

echo "::error::GitHub App /healthz did not become ready within 30 seconds"
docker logs "${container}" >&2
exit 1
