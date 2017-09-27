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
mruby_search( Operation *op, SlapReply *rs )
{
	struct mruby_info *info = (struct mruby_info *) op->o_bd->be_private;
	int rc;
	mrb_state *mrb = NULL;
	mrb_sym mid;
	mrb_value arg;
	mrb_value ret;

	Debug( LDAP_DEBUG_ARGS, "==> mruby_search\n", 0, 0, 0);
	mrb = mrb_open();
	if(!mrb){
		Debug( LDAP_DEBUG_ANY, "==> mruby_search: mrb_open() failed.\n",
		       0, 0, 0);
		goto done;
	}
	rc = mruby_load_file(mrb, info->file);
	if (rc) {
		Debug( LDAP_DEBUG_ANY,
			   "==> mruby_search: mruby_load_file(%s) failed.\n",
		       info->file, 0, 0);
		rs->sr_text = "mruby: internal error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}
	mid = mrb_intern_str(mrb, mrb_str_new_lit(mrb, "search"));
	if (!mrb_obj_respond_to(
			mrb, mrb_obj_class(mrb, mrb_top_self(mrb)), mid)) {
		rs->sr_text = "mruby: not supported";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}
	arg = mruby_arg(mrb, op);
	ret = mrb_funcall_argv(mrb, mrb_top_self(mrb), mid, 1, &arg);

	if (mrb_array_p(ret)) {

	} else if (mrb_fixnum_p(ret)) {
		rs->sr_err = mrb_fixnum(ret);
		goto done;
	} else if(mrb_exception_p(ret)) {
		mrb_print_error(mrb);
		mrb_print_backtrace(mrb);
		rs->sr_text = "mruby: internal error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	} else {
		Debug(LDAP_DEBUG_ANY, "==> mruby_search: invalid return %s\n",
			  mrb_string_value_cstr(mrb, &ret), 0, 0);
		rs->sr_text = "mruby: invalid return";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

	int i;
	Entry *e;
	const char *text;
	struct berval bv[2];
	AttributeDescription *ad = NULL;

	for(i=0; i < RARRAY_LEN(ret); i++){
		mrb_value rentry = mrb_ary_ref( mrb, ret, i );
		if ( !mrb_string_p(rentry)) {
			continue;
		}
		e = str2entry(mrb_str_to_cstr(mrb, rentry));
		if (!e) {
			Debug( LDAP_DEBUG_ANY,
				   "==> mruby_search: invalid entry\n",
				   0, 0, 0);
			continue;
		}
		rs->sr_entry = e;
		rs->sr_flags = 0;
		rs->sr_attrs = op->ors_attrs;
		rs->sr_operational_attrs = NULL;
		send_search_entry( op, rs );
		rs->sr_entry = NULL;
		entry_free(e);
	}
done:
	send_ldap_result( op, rs );
	if (mrb) {
		mrb_close(mrb);
	}
	return LDAP_SUCCESS;
}

/*
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
