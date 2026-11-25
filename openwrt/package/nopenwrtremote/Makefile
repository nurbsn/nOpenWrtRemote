include $(TOPDIR)/rules.mk

PKG_NAME:=nopenwrtremote
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=Marek Mucha <nurbsn@gmail.com>

PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

SECP256K1_VERSION:=0.6.0
SECP256K1_FILE:=secp256k1-$(SECP256K1_VERSION).tar.gz

define Download/secp256k1
  URL:=https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v$(SECP256K1_VERSION).tar.gz
  FILE:=$(SECP256K1_FILE)
  HASH:=785bb98e7d6705c51c8dfa8ac3af6aa2ccfa3774714d51c0b9e28fac1146e9f1
endef
$(eval $(call Download,secp256k1))

CMAKE_OPTIONS += \
	-DNORT_BUILD_TESTS=OFF \
	-DSECP256K1_SOURCE_DIR=$(PKG_BUILD_DIR)/third_party/secp256k1-$(SECP256K1_VERSION)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/third_party
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	tar -xzf $(DL_DIR)/$(SECP256K1_FILE) -C $(PKG_BUILD_DIR)/third_party
endef

define Package/nopenwrtremote
  SECTION:=net
  CATEGORY:=Network
  TITLE:=nOpenWrtRemote ultra-light C11 E2EE Nostr agent
  URL:=https://github.com/nurbsn/nOpenWrtRemote
  DEPENDS:=+libmbedtls +libjson-c +ca-bundle +libpthread
endef

define Package/nopenwrtremote/description
  Ultra-lightweight pure C11 outbound-only NORT-1 agent (Nostr NIP-44 v2 + AES-256-GCM)
  for OpenWrt routers including 16 MB flash devices.
endef

define Package/nopenwrtremote/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nopenwrtremote-agent $(1)/usr/bin/nopenwrtremote-agent
endef

$(eval $(call BuildPackage,nopenwrtremote))
