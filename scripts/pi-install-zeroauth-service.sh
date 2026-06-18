#!/usr/bin/env bash
set -euo pipefail

repo_dir="${1:-$(pwd)}"
repo_dir="$(cd "$repo_dir" && pwd)"
service_user="${OURA_SERVICE_USER:-$(id -un)}"
unit_template="$repo_dir/systemd/oura-zeroauth-chase.service"
unit_dest="/etc/systemd/system/oura-zeroauth-chase.service"

if [[ ! -f "$unit_template" ]]; then
  echo "missing unit template: $unit_template" >&2
  exit 1
fi

chmod 0755 "$repo_dir/scripts/pi-zeroauth-chase.sh"
repo_dir_escaped="${repo_dir//\\/\\\\}"
repo_dir_escaped="${repo_dir_escaped//&/\\&}"
service_user_escaped="${service_user//\\/\\\\}"
service_user_escaped="${service_user_escaped//&/\\&}"
sed \
  -e "s|@OURA_REPO_DIR@|$repo_dir_escaped|g" \
  -e "s|@OURA_SERVICE_USER@|$service_user_escaped|g" \
  "$unit_template" | sudo tee "$unit_dest" >/dev/null
sudo chmod 0644 "$unit_dest"
sudo systemctl daemon-reload
sudo systemctl enable oura-zeroauth-chase.service
sudo systemctl restart oura-zeroauth-chase.service
sudo systemctl --no-pager --lines=30 status oura-zeroauth-chase.service
