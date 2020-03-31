FROM rust:1

LABEL maintainer="Frank Fang <frank@origo.network>"
LABEL version=0.1

RUN apt-get -q -y update
RUN apt-get install -y \
	cmake \
	gcc \
	g++ \
    libgflags-dev \
	make \
	libudev-dev \
	rhash
