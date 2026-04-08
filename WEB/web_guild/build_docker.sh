#!/bin/sh
docker rm -f web_guild
docker build -t web_guild .
docker run --name=web_guild --rm -p1337:1337 -it web_guild