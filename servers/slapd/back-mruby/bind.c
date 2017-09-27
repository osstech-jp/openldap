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

#include "back-mruby.h"

int
mruby_bind(Operation *op, SlapReply *rs)
{
	struct mruby_info *info = (struct mruby_info *) op->o_bd->be_private;
	mrb_state *mrb = NULL;
	mrb_sym mid;
	mrb_value arg;
	mrb_value ret;
	mrb_value exc;
	int rc;

	Debug( LDAP_DEBUG_ARGS, "==> mruby_bind: dn: %s\n",
		   op->o_req_dn.bv_val, 0, 0);

	/* allow noauth binds */
	switch ( be_rootdn_bind( op, NULL ) ) {
	case LDAP_SUCCESS:
		/* frontend will send result */
		return rs->sr_err = LDAP_SUCCESS;
	default:
		/* give the database a chance */
		/* NOTE: this behavior departs from that of other backends,
         * since the others, in case of password checking failure
         * do not give the database a chance.  If an entry with
         * rootdn's name does not exist in the database the result
         * will be the same.  See ITS#4962 for discussion. */
		break;
	}

	mrb = mrb_open();
	if(!mrb){
		Debug( LDAP_DEBUG_ANY,
			   "==> mruby_bind: mrb_open() failed.\n",
			   0, 0, 0);
		rs->sr_text = "mruby: open error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}
	rc = mruby_load_file(mrb, info->file);
	if (rc) {
		Debug( LDAP_DEBUG_ANY,
		       "==> muby_bind: mruby_load_file(%s) failed.\n",
		       info->file, 0, 0);
		rs->sr_text = "mruby: load error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}
	mid = mrb_intern_str(mrb, mrb_str_new_lit(mrb, "bind"));
	if (!mrb_obj_respond_to(
			mrb, mrb_obj_class(mrb, mrb_top_self(mrb)), mid)) {
		rs->sr_text = "mruby: not supported";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}
	arg = mruby_arg(mrb, op);
	ret = mrb_funcall_argv(mrb, mrb_top_self(mrb), mid, 1, &arg);
	if(mrb_fixnum_p(ret)) {
		rs->sr_err = mrb_fixnum(ret);
	} else if (mrb_exception_p(ret)) {
		exc = mrb_funcall(mrb, ret, "inspect", 0);
		Debug( LDAP_DEBUG_ANY, "==> mruby_bind: exception %s\n",
		       mrb_string_value_cstr(mrb, &exc), 0, 0);
		rs->sr_text = "mruby: internal error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	} else {
		Debug(LDAP_DEBUG_ANY, "==> mruby_bind: invalid return %s\n",
			  mrb_string_value_cstr(mrb, &ret), 0, 0);
		rs->sr_text = "mruby: invalid return";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}
done:
	send_ldap_result( op, rs );
	if (mrb) {
		mrb_close(mrb);
	}
	return rs->sr_err;
}
/*
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
