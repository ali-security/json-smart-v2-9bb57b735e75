#!/bin/sh
# Keep the job open until Travis has archived this job's log up to the Maven
# result line, so the harness harvests the full test output. after_script
# cannot change the build result; this only waits.
URL="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
CAP=${1:-1800}
waited=0
while [ "$waited" -lt "$CAP" ]; do
  if curl -fsSL "$URL" 2>/dev/null | grep -Eq 'BUILD (SUCCESS|FAILURE)'; then
    echo "log archived after ${waited}s"
    exit 0
  fi
  echo "waiting for log archive... (${waited}s)"
  sleep 20
  waited=$((waited + 20))
done
echo "gave up waiting after ${CAP}s"
exit 0
