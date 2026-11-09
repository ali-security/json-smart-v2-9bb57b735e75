#!/bin/sh
# Print per-suite totals and every skipped test with its reason from the
# surefire XML reports.
cd json-smart/target/surefire-reports 2>/dev/null || { echo "no surefire reports"; exit 0; }
grep -h -o '<testsuite [^>]*>' TEST-*.xml | sed -E 's/.*name="([^"]*)".*tests="([0-9]+)".*/\1 tests=\2/' | sort
awk -F'"' '/<testcase /{tc=$0} /<skipped/{print "SKIPPED: " tc " :: " $0}' TEST-*.xml
