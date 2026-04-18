#!/usr/bin/env bash

set -euo pipefail

apt-get update
apt-get install -y libfido2-dev libfido2-1 pkg-config e2fsprogs
