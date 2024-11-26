#!/bin/bash
set -euo pipefail

# The upstream soundness check only supports _excluding_ specific files using
# an ignore file, but we want to only _include_ some specific files based on
# patterns. That's fine, we'll invert the predicate here to create the ignore
# file on the fly, then run the same command as the upstream soundness check.
repo_root=$(git rev-parse --show-toplevel)
git -C "${repo_root}" ls-files \
    '*.swift' \
    ':(exclude)*/*Boring*/*.swift' \
    ':(exclude)*_boring.swift' \
    > "${repo_root}/.swiftformatignore"
