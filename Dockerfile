FROM ubuntu:14.04

RUN apt-get update && \
    apt-get install -qy wget libncurses-dev lsb libusb-dev libreadline-dev libreadline6 libqt4-dev

RUN wget https://netix.dl.sourceforge.net/project/devkitpro/devkitARM/devkitARM_r46/devkitARM_r46-x86_64-linux.tar.bz2 && \
    tar xf devkitARM_r46-x86_64-linux.tar.bz2 && \
    rm -f devkitARM_r46-x86_64-linux.tar.bz2

ENV DEVKITPRO /proxmark3
ENV DEVKITARM /devkitARM
ENV PATH $PATH:$DEVKITARM/bin

ADD . /proxmark3

WORKDIR /proxmark3

RUN make
