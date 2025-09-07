#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source backup.env

rsync --archive --no-links "$SCRIPT_DIR/" "$BACKUP_DESTINATION"
