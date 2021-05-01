#!/usr/bin/env bash

docker exec -it `docker ps | grep ras-passport-example | awk '{print $1}'` /bin/bash
