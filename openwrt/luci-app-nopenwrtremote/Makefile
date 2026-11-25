include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-nopenwrtremote
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=Marek Mucha <nurbsn@gmail.com>

LUCI_TITLE:=LuCI support for nOpenWrtRemote (Zero-Knowledge E2EE Remote Access)
LUCI_DEPENDS:=+luci-base +nopenwrtremote
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
