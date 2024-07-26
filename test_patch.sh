#!/bin/bash
git apply ~/elliot/doca-psp-sample-app/hitless_patches.diff
apply_exit_code=$?
if [ $apply_exit_code -eq 0 ]; then
  exit 1
else
  exit 0
fi