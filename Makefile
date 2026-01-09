PLUGIN_NAME=		nmap
PLUGIN_VERSION=		1.13
PLUGIN_COMMENT=		Nmap network scanner WebUI
PLUGIN_DEPENDS=		nmap
PLUGIN_WWW=		https://nmap.org/

.if exists(${.CURDIR}/Mk/plugins.mk)
PLUGINSDIR=		${.CURDIR}
.include "Mk/plugins.mk"
.else
.include "../../Mk/plugins.mk"
.endif
