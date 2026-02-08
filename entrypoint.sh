#!/bin/bash
set -e
chown -R openclaw:openclaw /data
exec gosu openclaw node src/server.js
