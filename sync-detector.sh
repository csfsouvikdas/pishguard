#!/bin/sh
# Keep the extension's copy of the detection engine identical to the server's.
cp shared/detector.js extension/detector.js && echo "synced"
