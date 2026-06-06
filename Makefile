include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-haproxy-advanced
PKG_VERSION:=0.1.0
PKG_RELEASE:=4
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=woffko <https://github.com/woffko>

LUCI_TITLE:=LuCI app for managing HAProxy HTTP/HTTPS reverse proxy services
LUCI_DEPENDS:=+luci-base +haproxy
LUCI_PKGARCH:=all
LUCI_URL:=https://github.com/woffko/luci-app-haproxy-advanced
LUCI_MAINTAINER:=woffko <https://github.com/woffko>

define Package/$(PKG_NAME)/conffiles
/etc/config/haproxy-advanced
endef

include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ] && [ -z "$${APK_INSTROOT}" ]; then
	if [ -f /etc/uci-defaults/luci-haproxy-advanced ]; then
		( . /etc/uci-defaults/luci-haproxy-advanced ) && \
		rm -f /etc/uci-defaults/luci-haproxy-advanced
	fi
	rm -f /tmp/luci-indexcache /tmp/luci-modulecache
fi
exit 0
endef

# call BuildPackage - OpenWrt buildroot signature
