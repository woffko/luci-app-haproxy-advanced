# SPDX-License-Identifier: MIT

include $(TOPDIR)/rules.mk

PKG_VERSION:=0.2.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=woffko <2505149+woffko@users.noreply.github.com>

LUCI_TITLE:=LuCI support for HAProxy Advanced (HTTPS reverse proxy)
LUCI_DESCRIPTION:=Web interface of haproxy-advanced: services published by host name, \
	listeners, backends, logins, ACME certificates, a runtime panel and a preview \
	of the generated HAProxy configuration.
LUCI_DEPENDS:=+luci-base +haproxy-advanced +ucode-mod-socket
LUCI_PKGARCH:=all
LUCI_URL:=https://github.com/woffko/luci-app-haproxy-advanced
LUCI_MAINTAINER:=$(PKG_MAINTAINER)

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
