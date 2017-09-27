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

#ifndef _BACK_MRUBY_H_
#define _BACK_MRUBY_H_

#include "portable.h"
#include "slap.h"

#include "mruby.h"
#include "mruby/compile.h"
#include "mruby/string.h"
#include "mruby/hash.h"
#include "mruby/array.h"
#include "mruby/variable.h"
#include "proto-mruby.h"

#define INT3 __asm__("int3");

typedef struct mruby_info {
	char *file;
} mruby_info;

int mruby_load_file(mrb_state *mrb, const char *file);
mrb_value mruby_arg(mrb_state *mrb, Operation *op);

#endif /* _BACK_MRUBY_H_ */

