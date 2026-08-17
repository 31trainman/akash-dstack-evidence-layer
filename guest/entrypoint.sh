#!/bin/sh
set -eu
python -m guest.challenge_client
printf '
Attestation challenge completed. Keeping container alive for inspection.
'
exec tail -f /dev/null
