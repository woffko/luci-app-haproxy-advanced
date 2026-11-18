# SPDX-License-Identifier: MIT

include $(TOPDIR)/rules.mk

PKG_NAME:=haproxy-advanced
PKG_VERSION:=0.2.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=woffko <2505149+woffko@users.noreply.github.com>

include $(INCLUDE_DIR)/package.mk

define Package/haproxy-advanced
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=HAProxy reverse proxy for publishing internal services
  URL:=https://github.com/woffko/luci-app-haproxy-advanced
  DEPENDS:=+haproxy +ucode +ucode-mod-fs +ucode-mod-uci +ucode-mod-ubus +ucode-mod-socket
  PKGARCH:=all
endef

define Package/haproxy-advanced/description
  Runs HAProxy as an HTTPS reverse proxy configured through UCI
  (/etc/config/haproxy-advanced): shared listeners with host-based routing,
  TLS passthrough by SNI, access rules, Basic Auth, rate limits, ACME
  certificates and firewall integration. The configuration is checked with
  haproxy -c before it is applied; a broken configuration never replaces a
  working one. luci-app-haproxy-advanced is its web interface.
endef

define Package/haproxy-advanced/conffiles
/etc/config/haproxy-advanced
endef

define Build/Compile
endef

define Package/haproxy-advanced/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) ./files/haproxy-advanced.init $(1)/etc/init.d/haproxy-advanced
	$(INSTALL_CONF) ./files/haproxy-advanced.config $(1)/etc/config/haproxy-advanced
	$(INSTALL_DIR) $(1)/usr/share/haproxy-advanced
	$(INSTALL_DATA) ./files/ucode/*.uc $(1)/usr/share/haproxy-advanced/
	$(INSTALL_DIR) $(1)/usr/libexec/haproxy-advanced
	$(INSTALL_BIN) ./files/haproxy-advanced-ctl $(1)/usr/libexec/haproxy-advanced/ctl
endef

$(eval $(call BuildPackage,haproxy-advanced))
