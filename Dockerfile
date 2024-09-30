FROM ubuntu:focal

ENV TZ=Etc/UTC
ENV TERM=xterm
ENV APPIMAGE_EXTRACT_AND_RUN=1
ARG DEBIAN_FRONTEND=noninteractive
ARG NPCAP_VERSION=1.13

RUN apt-get update
RUN apt-get install -y build-essential pkg-config git zip wget file
RUN apt-get install -y g++-mingw-w64-i686
RUN apt-get install -y libpcap-dev libnl-3-dev libnl-route-3-dev

RUN mkdir -p /usr/src
WORKDIR /usr/src

ADD "https://api.github.com/repos/jclehner/nmrpflash/commits?per_page=1" latest_commit
RUN git clone https://github.com/jclehner/nmrpflash

WORKDIR /usr/src/nmrpflash
RUN wget -O npcap-sdk.zip https://npcap.com/dist/npcap-sdk-${NPCAP_VERSION}.zip
RUN unzip npcap-sdk.zip -d Npcap

ARG CACHEBUST=1

RUN make clean
RUN make release/linux-appimage
RUN make MINGW=i686-w64-mingw32- release release/win32

