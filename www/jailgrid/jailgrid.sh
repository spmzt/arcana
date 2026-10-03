#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# PROVIDE: jailgrid
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown
#
# The jailgrid console: kore(1) with jailgrid.so.  In /etc/rc.conf:
#
# jailgrid_enable (bool):	Set to "YES" to run the console.
# jailgrid_config (str):	kore(1) configuration.
#				Default: /usr/local/etc/jailgrid/kore.conf
# jailgrid_web_conf (str):	The console's own configuration.
#				Default: /usr/local/etc/jailgrid/web.conf

. /etc/rc.subr

name="jailgrid"
rcvar="jailgrid_enable"

load_rc_config $name

: ${jailgrid_enable:="NO"}
: ${jailgrid_config:="/usr/local/etc/jailgrid/kore.conf"}
: ${jailgrid_web_conf:="/usr/local/etc/jailgrid/web.conf"}

command="/usr/local/bin/kore"
# kore(1) 4.3 stays in the foreground unless told to daemonise.
command_args="-d -c ${jailgrid_config}"
pidfile="/var/run/jailgrid.pid"
required_files="${jailgrid_config} ${jailgrid_web_conf}"
jailgrid_env="JAILGRID_WEB_CONF=${jailgrid_web_conf}"

run_rc_command "$1"
