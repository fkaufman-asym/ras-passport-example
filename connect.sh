#!/usr/bin/env bash

docker exec -it `docker ps | grep ras-passport-example_py-dev | awk '{print $1}'` /bin/bash
