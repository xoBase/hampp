#!/bin/sh
# Print what this HAMPP installation supports, or say that HAMPP is unavailable.
if ! command -v hampp >/dev/null 2>&1; then
    echo "hampp: not found" >&2
    exit 1
fi
exec hampp capabilities --json
