FROM ubuntu:noble

ENV TZ=Etc/UTC
ENV TERM=xterm
ENV APPIMAGE_EXTRACT_AND_RUN=1
ENV LANG=C.UTF-8
ENV LC_ALL=${LANG}
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y build-essential pkg-config git
RUN apt-get install -y zip 7zip
RUN apt-get install -y file
RUN apt-get install -y g++-mingw-w64-i686
#RUN apt-get install -y imagemagick
RUN apt-get install -y libpcap-dev libnl-3-dev libnl-route-3-dev
RUN apt-get install -y libwxgtk3.2-dev
RUN apt-get install -y vim-tiny
RUN apt-get install -y pipx
RUN apt-get install -y wget
RUN apt-get install -y patchelf

ENV PIPX_BIN_DIR=/usr/local/bin
ENV PIPX_MAN_DIR=/usr/local/man
RUN pipx install cmake

ARG LINUXDEPLOY_URL=https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
ARG LINUXDEPLOY=/usr/local/bin/linuxdeploy-x86_64
RUN wget -O ${LINUXDEPLOY} ${LINUXDEPLOY_URL}
RUN chmod +x ${LINUXDEPLOY}

RUN mkdir -p /usr/src/nmrpflash
WORKDIR /usr/src/nmrpflash

