CC = $(CROSS)gcc
STRIP = $(CROSS)strip
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
VERSION := $(shell if [ -d .git ] && which git 2>&1 > /dev/null; then git describe --always | tail -c +2; else echo $$STANDALONE_VERSION; fi)
CFLAGS += -Wall -g -DNMRPFLASH_VERSION=\"$(VERSION)\"
SUFFIX ?=
NPCAP_SDK = 1.13
ARCH := $(shell uname -m)
LINUXDEPLOY = ./linuxdeploy-$(ARCH).AppImage
TMP := $(shell mktemp -d)
APPDIR = $(TMP)/AppDir
AFL = afl-gcc
DOCKER_BUILD_NAME=nmrpflash
DOCKER_CONTAINER_NAME=$(DOCKER_BUILD_NAME)-container

nmrpflash_OBJ = nmrp.o tftp.o ethsock.o util.o

ifdef MINGW
	SUFFIX = .exe
	CC = $(MINGW)gcc
	STRIP = $(MINGW)strip
	WINDRES = $(MINGW)windres
	CFLAGS += -DWIN32_LEAN_AND_MEAN
	CFLAGS += -D_WIN32_WINNT=0x0600
	CFLAGS += -D__USE_MINGW_ANSI_STDIO
	CFLAGS += "-I./Npcap/Include"
	LDFLAGS += -lwpcap
	LDFLAGS += -lPacket
	LDFLAGS += -liphlpapi
	LDFLAGS += -lws2_32
	LDFLAGS += -ladvapi32
	LDFLAGS += "-L./Npcap/Lib"
	nmrpflash_OBJ += windres.o
else ifeq ($(shell uname -s),Linux)
	CFLAGS += $(shell $(PKG_CONFIG) libnl-route-3.0 --cflags)
	CFLAGS += $(shell $(PKG_CONFIG) libpcap --cflags)
	LDFLAGS += $(shell $(PKG_CONFIG) libnl-route-3.0 --libs)
	LDFLAGS += $(shell $(PKG_CONFIG) libpcap --libs)
	AFL = afl-gcc
else
	LDFLAGS += -lpcap
ifeq ($(shell uname -s),Darwin)
	AFL=afl-clang
	TARGETS ?= -arch x86_64 -arch arm64
	CFLAGS += $(TARGETS)
	LDFLAGS += -framework CoreFoundation -framework SystemConfiguration $(TARGETS)
endif
endif

.PHONY: clean install release release/macos release/linux release/win32

nmrpflash$(SUFFIX): main.o $(nmrpflash_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

t_tftp$(SUFFIX): t_tftp.o $(nmrpflash_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c nmrpd.h
	$(CC) -c $(CFLAGS) $< -o $@

windres.o: nmrpflash.rc nmrpflash.manifest nmrpflash.ico
	$(WINDRES) $< -o $@

fuzz_nmrp: tftp.c util.c nmrp.c fuzz.c
	$(AFL) $(CFLAGS) -DNMRPFLASH_FUZZ $^ -o $@

fuzz_tftp: tftp.c util.c nmrp.c fuzz.c
	$(AFL) $(CFLAGS) -DNMRPFLASH_FUZZ -DNMRPFLASH_FUZZ_TFTP $^ -o $@

dofuzz_tftp: fuzz_tftp
	echo core | sudo tee /proc/sys/kernel/core_pattern
	echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
	afl-fuzz -i fuzzin/tftp -o fuzzout/tftp -- ./fuzz_tftp fuzzin/tftp.bin
	echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

clean:
	rm -f $(nmrpflash_OBJ) main.o t_tftp.o nmrpflash*.AppImage nmrpflash nmrpflash.exe fuzz_nmrp fuzz_tftp

install: nmrpflash
	install -d $(PREFIX)/bin
	install -s -m 755 nmrpflash $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/bin/nmrpflash

$(LINUXDEPLOY):
	wget -q -O $@ https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/$(shell basename $@)
	chmod +x $@

nmrpflash-$(ARCH).AppImage: $(LINUXDEPLOY) release
	rm -rf $(APPDIR)
	mkdir -p $(APPDIR)
	$(LINUXDEPLOY) --appdir $(APPDIR) -e nmrpflash -i nmrpflash.svg -o appimage --create-desktop-file

release/macos: release
	zip nmrpflash-$(VERSION)-macos.zip nmrpflash

release/linux: release
	zip nmrpflash-$(VERSION)-linux.zip nmrpflash

release/linux-appimage: nmrpflash-$(ARCH).AppImage
	mv $< $(TMP)/nmrpflash
	cd $(TMP); zip release.zip nmrpflash
	mv $(TMP)/release.zip nmrpflash-$(VERSION)-linux-$(ARCH).zip

release/win32:
	zip -X nmrpflash-$(VERSION)-win32.zip nmrpflash.exe

release: clean nmrpflash$(SUFFIX)
	$(STRIP) nmrpflash$(SUFFIX)

nmrpflash.ico: nmrpflash.svg
	convert -background transparent -define icon:auto-resize=256,64,48,32,16 $< $@

build-release-with-docker:
	docker build --build-arg CACHEBUST=$(shell date +%s) --build-arg NPCAP_SDK=$(NPCAP_SDK) --progress=plain -t $(DOCKER_BUILD_NAME) .
	-docker rm $(DOCKER_CONTAINER_NAME) &> /dev/null
	docker create --name $(DOCKER_CONTAINER_NAME) nmrpflash
	docker cp $(DOCKER_CONTAINER_NAME):/usr/src/nmrpflash/nmrpflash-$(VERSION)-linux-$(ARCH).zip .
	docker cp $(DOCKER_CONTAINER_NAME):/usr/src/nmrpflash/nmrpflash-$(VERSION)-win32.zip .
	docker rm $(DOCKER_CONTAINER_NAME)
