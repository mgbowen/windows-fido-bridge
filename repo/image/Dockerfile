ARG DISTRIBUTION
FROM debian:$DISTRIBUTION

RUN apt-get update \
 && apt-get install --no-install-recommends -yq \
        build-essential ca-certificates cmake file g++-mingw-w64-x86-64 git \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir /build \
 && chmod 777 /build
