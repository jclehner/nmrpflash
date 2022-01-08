#!/bin/bash

GSL_VERSION=3.1.0

curl -L "https://github.com/microsoft/GSL/archive/refs/tags/v${GSL_VERSION}.tar.gz" > gsl.tar.gz

mkdir -p include
tar --strip-components=1 --wildcards -xvf gsl.tar.gz '*/include/'
