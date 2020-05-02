FROM debian:bullseye

ADD etc/ /etc/
WORKDIR /openssh-client

RUN apt-get update \
 && apt-get install --no-install-recommends -yq devscripts \
 && apt-get build-dep -yq openssh-client \
 && apt-get source openssh-client

ADD . /
