#!/bin/bash
# Cleanup script for removing tracked build artifacts and large files from git
# Run this ONCE to clean up the repository

set -e

echo "JoyfulJay Repository Cleanup"
echo "============================"
echo ""
echo "This script will remove the following from git tracking:"
echo "  - Compiled extensions (*.so, *.c, *.html in extensions/)"
echo "  - Large benchmark data (benchmarks/data/)"
echo "  - Build artifacts (build/, __pycache__/)"
echo ""
echo "The files will remain on disk but will no longer be tracked."
echo ""

read -p "Continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

cd "$(dirname "$0")/.."

echo ""
echo "Step 1: Removing compiled extensions from git..."
git rm -r --cached src/joyfuljay/extensions/*.c 2>/dev/null || true
git rm -r --cached src/joyfuljay/extensions/*.html 2>/dev/null || true
git rm -r --cached src/joyfuljay/extensions/*.so 2>/dev/null || true
git rm -r --cached src/joyfuljay/extensions/build 2>/dev/null || true

echo "Step 2: Removing large benchmark data from git..."
git rm -r --cached benchmarks/data/wireshark_samples 2>/dev/null || true
git rm -r --cached benchmarks/data/bigFlows.pcap 2>/dev/null || true

echo "Step 3: Removing __pycache__ directories from git..."
find . -name "__pycache__" -type d -exec git rm -r --cached {} + 2>/dev/null || true

echo "Step 4: Removing build directories from git..."
git rm -r --cached build 2>/dev/null || true
git rm -r --cached dist 2>/dev/null || true
git rm -r --cached "*.egg-info" 2>/dev/null || true

echo ""
echo "Step 5: Staging .gitignore updates..."
git add .gitignore

echo ""
echo "Done! Now review the changes with:"
echo "  git status"
echo "  git diff --cached --stat"
echo ""
echo "Then commit with:"
echo "  git commit -m 'chore: remove build artifacts and large files from tracking'"
echo ""
echo "Note: The files remain on disk. Delete manually if needed:"
echo "  rm -rf src/joyfuljay/extensions/build"
echo "  rm -rf benchmarks/data/wireshark_samples"
echo "  rm benchmarks/data/bigFlows.pcap"
