# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel block device drivers.
#
# 12 June 2000, Christoph Hellwig <hch@infradead.org>
# Rewritten to use lists instead of if-statements.
#

obj-$(CONFIG_MAC_FLOPPY)	+= swim3.o
obj-$(CONFIG_BLK_DEV_SWIM)	+= swim_mod.o
obj-$(CONFIG_BLK_DEV_FD)	+= floppy.o
obj-$(CONFIG_AMIGA_FLOPPY)	+= amiflop.o
obj-$(CONFIG_PS3_DISK)		+= ps3disk.o
obj-$(CONFIG_PS3_VRAM)		+= ps3vram.o
obj-$(CONFIG_ATARI_FLOPPY)	+= ataflop.o
obj-$(CONFIG_AMIGA_Z2RAM)	+= z2ram.o
obj-$(CONFIG_BLK_DEV_RAM)	+= brd.o
obj-$(CONFIG_BLK_DEV_LOOP)	+= loop.o
obj-$(CONFIG_BLK_DEV_DAC960)	+= DAC960.o
obj-$(CONFIG_XILINX_SYSACE)	+= xsysace.o
obj-$(CONFIG_CDROM_PKTCDVD)	+= pktcdvd.o
obj-$(CONFIG_SUNVDC)		+= sunvdc.o
obj-$(CONFIG_BLK_DEV_SKD)	+= skd.o

obj-$(CONFIG_BLK_DEV_UMEM)	+= umem.o
obj-$(CONFIG_BLK_DEV_NBD)	+= nbd.o
obj-$(CONFIG_BLK_DEV_CRYPTOLOOP) += cryptoloop.o

obj-$(CONFIG_VIRTIO_BLK)	+= virtio_blk.o

obj-$(CONFIG_BLK_DEV_SX8)	+= sx8.o

obj-$(CONFIG_XEN_BLKDEV_FRONTEND)	+= xen-blkfront.o
obj-$(CONFIG_XEN_BLKDEV_BACKEND)	+= xen-blkback/
obj-$(CONFIG_BLK_DEV_DRBD)     += drbd/
obj-$(CONFIG_BLK_DEV_RBD)     += rbd.o
obj-$(CONFIG_BLK_DEV_PCIESSD_MTIP32XX)	+= mtip32xx/

obj-$(CONFIG_BLK_DEV_RSXX) += rsxx/
obj-$(CONFIG_ZRAM) += zram/

obj-$(CONFIG_BLK_DEV_NULL_BLK)	+= null_blk.o
null_blk-objs	:= null_blk_main.o
null_blk-$(CONFIG_BLK_DEV_ZONED) += null_blk_zoned.o

skd-y		:= skd_main.o
swim_mod-y	:= swim.o swim_asm.o

# SPDM stuff
SPDM_DIR?= /opt/libspdm
SPDM_HEADERS = $(SPDM_DIR)/include
SPDM_INCLUDE =  \
        -I $(SPDM_HEADERS) \
        -I $(SPDM_HEADERS)/hal \
        -I $(SPDM_HEADERS)/hal/x64 \
        -I $(SPDM_HEADERS)/library \
        -I $(SPDM_HEADERS)/industry_standard \
        -I $(SPDM_DIR)/library/spdm_common_lib \
        -I $(SPDM_DIR)/library/spdm_requester_lib


# # ccflags-y += $(SPDM_INCLUDE)
CFLAGS_virtio_blk.o = $(SPDM_INCLUDE)
CFLAGS_spdm_glue.o = $(SPDM_INCLUDE)

SPDM_BUILD_DIR?= $(SPDM_DIR)/build_buildroot

SPDM_CRYPTO?= mbedtls

SPDM_LIBS = \
        $(SPDM_BUILD_DIR)/lib/librnglib.a \
        $(SPDM_BUILD_DIR)/lib/libmemlib.a \
        $(SPDM_BUILD_DIR)/lib/libmalloclib.a \
        $(SPDM_BUILD_DIR)/lib/libdebuglib.a \
        $(SPDM_BUILD_DIR)/lib/libcryptlib_$(SPDM_CRYPTO).a \
        $(SPDM_BUILD_DIR)/lib/lib$(SPDM_CRYPTO)lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_crypt_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_secured_message_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_requester_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_device_secret_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_common_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_transport_mctp_lib.a\
        $(SPDM_BUILD_DIR)/lib/libspdm_transport_pcidoe_lib.a

SPDM_DIR_SUFIX = _spdmlib
SPDM_OBJ  := $(foreach libfile, $(SPDM_LIBS), $(shell ar t $(libfile) | sed s-^-$$(basename $(libfile))$(SPDM_DIR_SUFIX)/-))
SPDM_TARGETS := $(addprefix $(src)/, $(SPDM_OBJ))

virtio_blk-objs := virtio_blk.o spdm_glue.o $(SPDM_OBJ)

$(SPDM_TARGETS): $(SPDM_LIBS)
	mkdir -p $$(dirname $@)
	cd $$(dirname $@); ar x $(SPDM_BUILD_DIR)/lib/$$(basename $$(dirname $@ | sed s/$(SPDM_DIR_SUFIX)//)) $$(basename $@)
