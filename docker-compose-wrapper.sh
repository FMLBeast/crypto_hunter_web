#!/bin/bash

# This is a wrapper script that calls the docker_manage.sh script in the docker directory
# with the provided arguments

# Load environment variables from .env file
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Change to the docker directory
cd docker

# Call the docker_manage.sh script
./docker_manage.sh "$@"
