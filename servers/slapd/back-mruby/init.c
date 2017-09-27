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
#include "config.h"

int mruby_back_open(BackendInfo *bi)
{
	mrb_state *mrb = NULL;
	mrb_value version;
	mrb = mrb_open();
	if(!mrb){
		Debug( LDAP_DEBUG_ANY,
			   "==> mruby_bind: mrb_open() failed.\n",
			   0, 0, 0);
		return -1;
	}
	version = mrb_const_get(mrb,
							mrb_obj_value(mrb->object_class),
							mrb_intern_lit(mrb, "MRUBY_DESCRIPTION"));
	Debug( LDAP_DEBUG_ANY, "back-mruby with %s\n",
		   mrb_str_to_cstr(mrb, version), 0, 0);
	mrb_close(mrb);
	return 0;
}

int mruby_back_destroy(BackendInfo *bi)
{
	Debug( LDAP_DEBUG_ARGS, "==> mruby_back_destroy\n", 0, 0, 0);
	return 0;
}

static int
mruby_db_open( BackendDB *be, ConfigReply *cr )
{
	struct mruby_info *ni = (struct mruby_info *) be->be_private;
	return 0;
}

static int
mruby_db_close( BackendDB *be, ConfigReply *cr )
{
	struct mruby_info *ni = (struct mruby_info *) be->be_private;
	return 0;
}

struct mruby_const_t {
	char *name;
	int value;
};

static struct mruby_const_t mruby_const[] = {
	{"LDAP_SUCCESS", LDAP_SUCCESS},
	{"LDAP_OPERATIONS_ERROR", LDAP_OPERATIONS_ERROR},
	{"LDAP_PROTOCOL_ERROR", LDAP_PROTOCOL_ERROR},
	{"LDAP_TIMELIMIT_EXCEEDED", LDAP_TIMELIMIT_EXCEEDED},
	{"LDAP_SIZELIMIT_EXCEEDED", LDAP_SIZELIMIT_EXCEEDED},
	{"LDAP_COMPARE_FALSE", LDAP_COMPARE_FALSE},
	{"LDAP_COMPARE_FALSE", LDAP_COMPARE_FALSE},
	{"LDAP_COMPARE_TRUE", LDAP_COMPARE_TRUE},
	{"LDAP_AUTH_METHOD_NOT_SUPPORTED", LDAP_AUTH_METHOD_NOT_SUPPORTED},
	{"LDAP_STRONG_AUTH_NOT_SUPPORTED", LDAP_STRONG_AUTH_NOT_SUPPORTED},
	{"LDAP_STRONG_AUTH_REQUIRED", LDAP_STRONG_AUTH_REQUIRED},
	{"LDAP_STRONGER_AUTH_REQUIRED", LDAP_STRONGER_AUTH_REQUIRED},
	{"LDAP_PARTIAL_RESULTS", LDAP_PARTIAL_RESULTS},
	{"LDAP_REFERRAL", LDAP_REFERRAL},
	{"LDAP_ADMINLIMIT_EXCEEDED", LDAP_ADMINLIMIT_EXCEEDED},
	{"LDAP_UNAVAILABLE_CRITICAL_EXTENSION", LDAP_UNAVAILABLE_CRITICAL_EXTENSION},
	{"LDAP_CONFIDENTIALITY_REQUIRED", LDAP_CONFIDENTIALITY_REQUIRED},
	{"LDAP_NO_SUCH_ATTRIBUTE", LDAP_NO_SUCH_ATTRIBUTE},
	{"LDAP_UNDEFINED_TYPE", LDAP_UNDEFINED_TYPE},
	{"LDAP_INAPPROPRIATE_MATCHING", LDAP_INAPPROPRIATE_MATCHING},
	{"LDAP_CONSTRAINT_VIOLATION", LDAP_CONSTRAINT_VIOLATION},
	{"LDAP_TYPE_OR_VALUE_EXISTS", LDAP_TYPE_OR_VALUE_EXISTS},
	{"LDAP_INVALID_SYNTAX", LDAP_INVALID_SYNTAX},
	{"LDAP_NO_SUCH_OBJECT", LDAP_NO_SUCH_OBJECT},
	{"LDAP_ALIAS_PROBLEM", LDAP_ALIAS_PROBLEM},
	{"LDAP_INVALID_DN_SYNTAX", LDAP_INVALID_DN_SYNTAX},
	{"LDAP_IS_LEAF", LDAP_IS_LEAF},
	{"LDAP_ALIAS_DEREF_PROBLEM", LDAP_ALIAS_DEREF_PROBLEM},
	{"LDAP_X_PROXY_AUTHZ_FAILURE", LDAP_X_PROXY_AUTHZ_FAILURE},
	{"LDAP_INAPPROPRIATE_AUTH", LDAP_INAPPROPRIATE_AUTH},
	{"LDAP_INVALID_CREDENTIALS", LDAP_INVALID_CREDENTIALS},
	{"LDAP_INSUFFICIENT_ACCESS", LDAP_INSUFFICIENT_ACCESS},
	{"LDAP_BUSY", LDAP_BUSY},
	{"LDAP_UNAVAILABLE", LDAP_UNAVAILABLE},
	{"LDAP_UNWILLING_TO_PERFORM", LDAP_UNWILLING_TO_PERFORM},
	{"LDAP_LOOP_DETECT", LDAP_LOOP_DETECT},
	{"LDAP_NAMING_VIOLATION", LDAP_NAMING_VIOLATION},
	{"LDAP_OBJECT_CLASS_VIOLATION", LDAP_OBJECT_CLASS_VIOLATION},
	{"LDAP_NOT_ALLOWED_ON_NONLEAF", LDAP_NOT_ALLOWED_ON_NONLEAF},
	{"LDAP_NOT_ALLOWED_ON_RDN", LDAP_NOT_ALLOWED_ON_RDN},
	{"LDAP_ALREADY_EXISTS", LDAP_ALREADY_EXISTS},
	{"LDAP_NO_OBJECT_CLASS_MODS", LDAP_NO_OBJECT_CLASS_MODS},
	{"LDAP_RESULTS_TOO_LARGE", LDAP_RESULTS_TOO_LARGE},
	{"LDAP_AFFECTS_MULTIPLE_DSAS", LDAP_AFFECTS_MULTIPLE_DSAS},
	{"LDAP_VLV_ERROR", LDAP_VLV_ERROR},
	{"LDAP_OTHER", LDAP_OTHER},
	{"LDAP_CUP_RESOURCES_EXHAUSTED", LDAP_CUP_RESOURCES_EXHAUSTED},
	{"LDAP_CUP_SECURITY_VIOLATION", LDAP_CUP_SECURITY_VIOLATION},
	{"LDAP_CUP_INVALID_DATA", LDAP_CUP_INVALID_DATA},
	{"LDAP_CUP_UNSUPPORTED_SCHEME", LDAP_CUP_UNSUPPORTED_SCHEME},
	{"LDAP_CUP_RELOAD_REQUIRED", LDAP_CUP_RELOAD_REQUIRED},
	{"LDAP_CANCELLED", LDAP_CANCELLED},
	{"LDAP_NO_SUCH_OPERATION", LDAP_NO_SUCH_OPERATION},
	{"LDAP_TOO_LATE", LDAP_TOO_LATE},
	{"LDAP_CANNOT_CANCEL", LDAP_CANNOT_CANCEL},
	{"LDAP_ASSERTION_FAILED", LDAP_ASSERTION_FAILED},
	{"LDAP_PROXIED_AUTHORIZATION_DENIED", LDAP_PROXIED_AUTHORIZATION_DENIED},
	{"LDAP_SYNC_REFRESH_REQUIRED", LDAP_SYNC_REFRESH_REQUIRED},
	{"LDAP_X_SYNC_REFRESH_REQUIRED", LDAP_X_SYNC_REFRESH_REQUIRED},
	{"LDAP_X_ASSERTION_FAILED", LDAP_X_ASSERTION_FAILED},
	{"LDAP_X_NO_OPERATION", LDAP_X_NO_OPERATION},
	/* errors */
	{"LDAP_SERVER_DOWN", LDAP_SERVER_DOWN},
	{"LDAP_LOCAL_ERROR", LDAP_LOCAL_ERROR},
	{"LDAP_ENCODING_ERROR", LDAP_ENCODING_ERROR},
	{"LDAP_DECODING_ERROR", LDAP_DECODING_ERROR},
	{"LDAP_TIMEOUT", LDAP_TIMEOUT},
	{"LDAP_AUTH_UNKNOWN", LDAP_AUTH_UNKNOWN},
	{"LDAP_FILTER_ERROR", LDAP_FILTER_ERROR},
	{"LDAP_USER_CANCELLED", LDAP_USER_CANCELLED},
	{"LDAP_PARAM_ERROR", LDAP_PARAM_ERROR},
	{"LDAP_NO_MEMORY", LDAP_NO_MEMORY},
	{"LDAP_CONNECT_ERROR", LDAP_CONNECT_ERROR},
	{"LDAP_NOT_SUPPORTED", LDAP_NOT_SUPPORTED},
	{"LDAP_CONTROL_NOT_FOUND", LDAP_CONTROL_NOT_FOUND},
	{"LDAP_NO_RESULTS_RETURNED", LDAP_NO_RESULTS_RETURNED},
	{"LDAP_MORE_RESULTS_TO_RETURN", LDAP_MORE_RESULTS_TO_RETURN},
	{"LDAP_CLIENT_LOOP", LDAP_CLIENT_LOOP},
	{"LDAP_REFERRAL_LIMIT_EXCEEDED", LDAP_REFERRAL_LIMIT_EXCEEDED},
	{"LDAP_X_CONNECTING", LDAP_X_CONNECTING},
	/* scope */
	{"LDAP_SCOPE_BASE", LDAP_SCOPE_BASE},
	{"LDAP_SCOPE_BASEOBJECT", LDAP_SCOPE_BASEOBJECT},
	{"LDAP_SCOPE_ONELEVEL", LDAP_SCOPE_ONELEVEL},
	{"LDAP_SCOPE_ONE", LDAP_SCOPE_ONE},
	{"LDAP_SCOPE_SUBTREE", LDAP_SCOPE_SUBTREE},
	{"LDAP_SCOPE_SUB", LDAP_SCOPE_SUB},
	{"LDAP_SCOPE_SUBORDINATE", LDAP_SCOPE_SUBORDINATE},
	{"LDAP_SCOPE_CHILDREN", LDAP_SCOPE_CHILDREN},
	{"LDAP_SCOPE_DEFAULT", LDAP_SCOPE_DEFAULT},
	{NULL, 0}
};

int mruby_load_file(mrb_state *mrb, const char *file){
	mrb_value top = mrb_top_self(mrb);
	FILE *fp;
	struct mruby_const_t *p;

	if ((fp = fopen(file, "r")) == NULL) {
		return -1;
	}
	mrb_load_file(mrb, fp);
	fclose(fp);

	for(p = mruby_const; p->name; p++){
		mrb_define_const(mrb, mrb->kernel_module, p->name,
						 mrb_fixnum_value(p->value));
	};
	return 0;
}

mrb_value mruby_arg(mrb_state *mrb, Operation *op){
	mrb_value arg;
	mrb_value req;

	/* request for search */
	AttributeName *an;
	mrb_value attrs;
	/* request for add */
	mrb_value entry;

	attrs = mrb_ary_new(mrb);
	arg = mrb_hash_new(mrb);
	mrb_hash_set(mrb, arg,
				 mrb_str_new_cstr(mrb, "dn"),
				 mrb_str_new_static(mrb,
									op->o_req_dn.bv_val,
									op->o_req_dn.bv_len));
	mrb_hash_set(mrb, arg,
				 mrb_str_new_cstr(mrb, "ndn"),
				 mrb_str_new_static(mrb,
									op->o_req_ndn.bv_val,
									op->o_req_ndn.bv_len));
	req = mrb_hash_new(mrb);
	mrb_hash_set(mrb, arg, mrb_str_new_cstr(mrb, "req"), req);
	switch (op->o_tag) {
	case LDAP_REQ_BIND:
		mrb_hash_set(mrb, req,
					 mrb_str_new_cstr(mrb, "cred"),
					 mrb_str_new_static(mrb,
										op->orb_cred.bv_val,
										op->orb_cred.bv_len));
		break;
	case LDAP_REQ_SEARCH:
		mrb_hash_set(mrb, req,
					 mrb_str_new_cstr(mrb, "scope"),
					 mrb_fixnum_value(op->ors_scope));
		mrb_hash_set(mrb, req,
					 mrb_str_new_cstr(mrb, "deref"),
					 mrb_fixnum_value(op->ors_deref));
		mrb_hash_set(mrb, req,
					 mrb_str_new_cstr(mrb, "slimit"),
					 mrb_fixnum_value(op->ors_slimit));
		mrb_hash_set(mrb, req,
					 mrb_str_new_cstr(mrb, "tlimit"),
					 mrb_fixnum_value(op->ors_tlimit));
		/*
		  TODO: struct slap_limits_set *rs_limit;
		*/
		mrb_hash_set(mrb, req,
					 mrb_str_new_cstr(mrb, "attrsonly"),
					 mrb_bool_value(op->ors_attrsonly));
		mrb_hash_set(mrb, req, mrb_str_new_cstr(mrb, "attrs"), attrs);
		for ( an = op->oq_search.rs_attrs; an && an->an_name.bv_val; an++ ) {
			mrb_ary_push(mrb, attrs,
						 mrb_str_new_static(mrb,
											an->an_name.bv_val,
											an->an_name.bv_len));
		}
		mrb_hash_set(mrb, req,
					 mrb_str_new_cstr(mrb, "filter"),
					 mrb_str_new_static(mrb,
										op->ors_filterstr.bv_val,
										op->ors_filterstr.bv_len));
		break;
	case LDAP_REQ_ADD:
		entry = mrb_hash_new(mrb);
		attrs = mrb_hash_new(mrb);
		mrb_hash_set(mrb, entry,
					 mrb_str_new_cstr(mrb, "dn"),
					 mrb_str_new_static(mrb,
										op->ora_e->e_name.bv_val,
										op->ora_e->e_name.bv_len));
		mrb_hash_set(mrb, entry,
					 mrb_str_new_cstr(mrb, "ndn"),
					 mrb_str_new_static(mrb,
										op->ora_e->e_nname.bv_val,
										op->ora_e->e_nname.bv_len));
		Attribute *ap;
		for ( ap = op->ora_e->e_attrs; ap ; ap = ap->a_next ) {
			int i;
			mrb_value vals;
			vals = mrb_ary_new(mrb);
			for(i = 0; i < ap->a_numvals; i++){
				mrb_ary_push(mrb, vals,
							 mrb_str_new_static(mrb,
												ap->a_vals[i].bv_val,
												ap->a_vals[i].bv_len));
			}
			mrb_hash_set(mrb, attrs,
						 mrb_str_new_static(mrb,
											ap->a_desc->ad_cname.bv_val,
											ap->a_desc->ad_cname.bv_len),
						 vals);
		}
		mrb_hash_set(mrb, entry, mrb_str_new_cstr(mrb, "attrs"), attrs);
		mrb_hash_set(mrb, req, mrb_str_new_cstr(mrb, "entry"), entry);
		/* call with ldif
		int len;
		mrb_hash_set(mrb, req,
					 mrb_str_new_cstr(mrb, "ldif"),
					 mrb_str_new_cstr(mrb, entry2str( op->ora_e, &len)));
		*/
		break;
	case LDAP_REQ_DELETE:
		break;
	}
	return arg;
}

/* Setup */
static int
mruby_db_init( BackendDB *be, ConfigReply *cr )
{
	struct mruby_info *mi = ch_calloc( 1, sizeof(struct mruby_info) );
	be->be_private = mi;
	be->be_cf_ocs = be->bd_info->bi_cf_ocs;
	return 0;
}

static int
mruby_db_destroy( Backend *be, ConfigReply *cr )
{
	struct mruby_info *mi = be->be_private;
	if ( mi->file ) {
		free(mi->file);
		mi->file = NULL;
	}
	free( be->be_private );
	return 0;
}

int
mruby_back_initialize( BackendInfo *bi )
{
	Debug( LDAP_DEBUG_TRACE,
		   "mruby_back_initialize: initialize mruby backend\n",
		   0, 0, 0);

	bi->bi_controls = 0;
	bi->bi_open = mruby_back_open;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = mruby_back_destroy;

	bi->bi_db_init = mruby_db_init;
	bi->bi_db_config = config_generic_wrapper;
	bi->bi_db_open = mruby_db_open;
	bi->bi_db_close = mruby_db_close;
	bi->bi_db_destroy = mruby_db_destroy;

	bi->bi_op_bind = mruby_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = mruby_search;
	bi->bi_op_compare = 0;
	bi->bi_op_modify = 0;
	bi->bi_op_modrdn = 0;
	bi->bi_op_add = mruby_add;
	bi->bi_op_delete = mruby_delete;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return mruby_back_init_cf( bi );
}

#if SLAPD_MRUBY == SLAPD_MOD_DYNAMIC

/* conditionally define the init_module() function */
SLAP_BACKEND_INIT_MODULE( mruby )

#endif /* SLAPD_MRUBY == SLAPD_MOD_DYNAMIC */

/*
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
