# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=2
inherit eutils autotools

DESCRIPTION="Snarf Windows executables off the wire (Driftnet for EXEs)"
HOMEPAGE="http://code.google.com/p/execap/"
SRC_URI="http://execap.googlecode.com/files/${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~x86 ~amd64"
IUSE=""

DEPEND=">=net-libs/libpcap-1.0.0
	>=dev-libs/openssl-0.9.8"
RDEPEND="${DEPEND}"

src_install() {

	emake DESTDIR="${D}" install || die "emake failed"

	dodir /var/log/execap \
	      /var/log/execap/exes || die "Failed to create core directories"

	dodoc ChangeLog \
	      README \
	      NEWS \
	      AUTHORS \
	      INSTALL \
	      LICENSE \
	      COPYING || die "Failed to install execap docs"
}
