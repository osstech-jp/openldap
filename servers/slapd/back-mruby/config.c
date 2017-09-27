/* mruby.c - the mruby backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2002-2017 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "back-mruby.h"
#include "config.h"

static ConfigDriver mruby_cf;

enum {
	MRUBY_FILE = 0
};

static ConfigTable mrubycfg[] = {
	{ "mrubyfile", "file", 2, 0, 0, ARG_MAGIC|MRUBY_FILE, mruby_cf,
	  "( OLcfgDbAt:8.1 NAME 'olcMRubyFile' "
	  "DESC 'MRuby file' "
	  "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ NULL }
};

static ConfigOCs mrubyocs[] = {
	{ "( OLcfgDbOc:8.1 "
	  "NAME 'olcMRubyConfig' "
	  "DESC 'MRuby backend ocnfiguration' "
	  "SUP olcDatabaseConfig "
	  "MAY ( olcMRubyFile ) )",
	  Cft_Database, mrubycfg },
	{ NULL }
};

static int
mruby_cf( ConfigArgs *c )
{
	struct mruby_info *info = (struct mruby_info *) c->be->be_private;
	if (c->op == SLAP_CONFIG_EMIT ) {
		switch( c->type ) {
		case MRUBY_FILE:
			if ( !info->file ) {
				return 1;
			}
			break;
		}
	}else {
		switch( c->type ) {
		case MRUBY_FILE:
			info->file = ch_strdup( c->argv[1] );
			break;
		}
	}
	return 0;
}

int
mruby_back_init_cf( BackendInfo *bi )
{
	bi->bi_cf_ocs = mrubyocs;
	return config_register_schema( mrubycfg, mrubyocs );
}
