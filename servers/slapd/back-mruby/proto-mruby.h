/* OpenLDAP MRuby backend */
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
/* ACKNOWLEDGEMENTS:
 * This work was developed by HAMANO Tsukasa <hamano@osstech.co.jp>
 */

#ifndef PROTO_MRUBY_H
#define PROTO_MRUBY_H

LDAP_BEGIN_DECL

extern int mruby_back_init_cf( BackendInfo *bi );

extern BI_op_bind    mruby_bind;
extern BI_op_add     mruby_add;
extern BI_op_search  mruby_search;
extern BI_op_delete  mruby_delete;

LDAP_END_DECL

#endif /* PROTO_MRUBY_H */
