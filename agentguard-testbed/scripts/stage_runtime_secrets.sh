#!/bin/sh
set -eu

stage_secret() {
  source_path=$1
  destination_path=$2
  owner_uid=$3
  owner_gid=$4
  temporary_path="${destination_path}.tmp"

  test -f "$source_path"
  cp "$source_path" "$temporary_path"
  chown "$owner_uid:$owner_gid" "$temporary_path"
  chmod 0400 "$temporary_path"
  mv -f "$temporary_path" "$destination_path"
}

umask 077
stage_secret \
  /run/source/signer-private-key \
  /var/lib/aegisledger-secrets/signer/signer-private-key \
  65532 65532
stage_secret \
  /run/source/signer-tls-key \
  /var/lib/aegisledger-secrets/signer/signer-tls-key \
  65532 65532
stage_secret \
  /run/source/api-client-tls-key \
  /var/lib/aegisledger-secrets/api/api-client-tls-key \
  10001 10001
