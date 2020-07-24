// SPDX-License-Identifier: LGPL-2.1+
/*
 *   Copyright (C) International Business Machines  Corp., 2007,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Modified by Namjae Jeon <linkinjeon@kernel.org>
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/posix_acl.h>
#include "smbacl.h"
#include "smb_common.h"
#include "server.h"

static const struct smb_sid cifsd_domain = {1, 4, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(21),
	 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* security id for everyone/world system group */
static const struct smb_sid creator_owner = {
	1, 1, {0, 0, 0, 0, 0, 3}, {0} };
/* security id for everyone/world system group */
static const struct smb_sid creator_group = {
	1, 1, {0, 0, 0, 0, 0, 3}, {cpu_to_le32(1)} };

/* security id for everyone/world system group */
static const struct smb_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };
/* security id for Authenticated Users system group */
static const struct smb_sid sid_authusers = {
	1, 1, {0, 0, 0, 0, 0, 5}, {cpu_to_le32(11)} };

/* S-1-22-1 Unmapped Unix users */
static const struct smb_sid sid_unix_users = {1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-22-2 Unmapped Unix groups */
static const struct smb_sid sid_unix_groups = { 1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * See http://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */

/* S-1-5-88 MS NFS and Apple style UID/GID/mode */

/* S-1-5-88-1 Unix uid */
static const struct smb_sid sid_unix_NFS_users = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-2 Unix gid */
static const struct smb_sid sid_unix_NFS_groups = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-3 Unix mode */
static const struct smb_sid sid_unix_NFS_mode = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(3), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * if the two SIDs (roughly equivalent to a UUID for a user or group) are
 * the same returns zero, if they do not match returns non-zero.
 */
static int
compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid)
{
	int i;
	int num_subauth, num_sat, num_saw;

	if ((!ctsid) || (!cwsid))
		return 1;

	/* compare the revision */
	if (ctsid->revision != cwsid->revision) {
		if (ctsid->revision > cwsid->revision)
			return 1;
		else
			return -1;
	}

	/* compare all of the six auth values */
	for (i = 0; i < NUM_AUTHS; ++i) {
		if (ctsid->authority[i] != cwsid->authority[i]) {
			if (ctsid->authority[i] > cwsid->authority[i])
				return 1;
			else
				return -1;
		}
	}

	/* compare all of the subauth values if any */
	num_sat = ctsid->num_subauth;
	num_saw = cwsid->num_subauth;
	num_subauth = num_sat < num_saw ? num_sat : num_saw;
	if (num_subauth) {
		for (i = 0; i < num_subauth; ++i) {
			if (ctsid->sub_auth[i] != cwsid->sub_auth[i]) {
				if (le32_to_cpu(ctsid->sub_auth[i]) >
					le32_to_cpu(cwsid->sub_auth[i]))
					return 1;
				else
					return -1;
			}
		}
	}

	return 0; /* sids compare/match */
}

static void
smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src)
{
	int i;

	dst->revision = src->revision;
	dst->num_subauth = min_t(u8, src->num_subauth, SID_MAX_SUB_AUTHORITIES);
	for (i = 0; i < NUM_AUTHS; ++i)
		dst->authority[i] = src->authority[i];
	for (i = 0; i < dst->num_subauth; ++i)
		dst->sub_auth[i] = src->sub_auth[i];
}

/*
 * change posix mode to reflect permissions
 * pmode is the existing mode (we only want to overwrite part of this
 * bits to set can be: S_IRWXU, S_IRWXG or S_IRWXO ie 00700 or 00070 or 00007
 */
static umode_t access_flags_to_mode(__le32 ace_flags, int type)
{
	__u32 flags = le32_to_cpu(ace_flags);
	umode_t mode = 0;

	if (flags & GENERIC_ALL) {
		mode = 0777;
		ksmbd_err("all perms\n");
		return mode;
	}
	if ((flags & GENERIC_WRITE) ||
			((flags & FILE_WRITE_RIGHTS) == FILE_WRITE_RIGHTS))
		mode = 0222;
	if ((flags & GENERIC_READ) ||
			((flags & FILE_READ_RIGHTS) == FILE_READ_RIGHTS))
		mode = 0444;
	if ((flags & GENERIC_EXECUTE) ||
			((flags & FILE_EXEC_RIGHTS) == FILE_EXEC_RIGHTS))
		mode = 0111;

	ksmbd_debug(SMB, "access flags 0x%x mode now %04o\n", flags, mode);

	return mode;
}

/*
 * Generate access flags to reflect permissions mode is the existing mode.
 * This function is called for every ACE in the DACL whose SID matches
 * with either owner or group or everyone.
 */
static void mode_to_access_flags(umode_t mode, umode_t bits_to_use,
				__u32 *pace_flags)
{
	/* reset access mask */
	*pace_flags = 0x0;

	/* bits to use are either S_IRWXU or S_IRWXG or S_IRWXO */
	mode &= bits_to_use;

	/*
	 * check for R/W/X UGO since we do not know whose flags
	 * is this but we have cleared all the bits sans RWX for
	 * either user or group or other as per bits_to_use
	 */
	if (mode & 0444)
		*pace_flags |= SET_FILE_READ_RIGHTS;
	if (mode & 0222)
		*pace_flags |= SET_FILE_WRITE_RIGHTS;
	if (mode & 0111)
		*pace_flags |= SET_FILE_EXEC_RIGHTS;

	ksmbd_debug(SMB, "mode: 0x%x, access flags now 0x%x\n",
		 mode, *pace_flags);
}

static __u16 fill_ace_for_sid(struct smb_ace *pntace,
			const struct smb_sid *psid, int flags, umode_t mode, umode_t bits)
{
	int i;
	__u16 size = 0;
	__u32 access_req = 0;

	pntace->type = ACCESS_ALLOWED;
	pntace->flags = flags;
	mode_to_access_flags(mode, bits, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	pntace->access_req = cpu_to_le32(access_req);

	pntace->sid.revision = psid->revision;
	pntace->sid.num_subauth = psid->num_subauth;
	for (i = 0; i < NUM_AUTHS; i++)
		pntace->sid.authority[i] = psid->authority[i];
	for (i = 0; i < psid->num_subauth; i++)
		pntace->sid.sub_auth[i] = psid->sub_auth[i];

	size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (psid->num_subauth * 4);
	pntace->size = cpu_to_le16(size);

	return size;
}

static void id_to_sid(unsigned int cid, uint sidtype, struct smb_sid *ssid)
{
	switch (sidtype) {
	case SIDOWNER:
		smb_copy_sid(ssid, &cifsd_domain);
		break;
	case SIDGROUP:
		smb_copy_sid(ssid, &sid_unix_groups);
		break;
	case SIDCREATOR_OWNER:
		smb_copy_sid(ssid, &creator_owner);
		return;
	case SIDCREATOR_GROUP:
		smb_copy_sid(ssid, &creator_group);
		return;
	default:
		return;
	}

	/* RID */
	ssid->sub_auth[ssid->num_subauth] = cid;
	ssid->num_subauth++;
}

static int sid_to_id(struct smb_sid *psid, uint sidtype, struct smb_fattr *fattr)
{
	int rc = 0;

	/*
	 * If we have too many subauthorities, then something is really wrong.
	 * Just return an error.
	 */
	if (unlikely(psid->num_subauth > SID_MAX_SUB_AUTHORITIES)) {
		ksmbd_err("%s: %u subauthorities is too many!\n",
			 __func__, psid->num_subauth);
		return -EIO;
	}

	if (sidtype == SIDOWNER) {
		kuid_t uid;
		uid_t id;

		id = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);
		uid = make_kuid(&init_user_ns, id);
		if (uid_valid(uid))
			fattr->cf_uid = uid;
	} else {
		kgid_t gid;
		gid_t id;
		
		id = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);
		gid = make_kgid(&init_user_ns, id);
		if (gid_valid(gid))
			fattr->cf_gid = gid;
	}

	return rc;
}

static void posix_state_to_acl(struct posix_acl_state *state, struct posix_acl_entry *pace)
{
		int i;

		pace->e_tag = ACL_USER_OBJ;
		pace->e_perm = state->owner.allow;

		for (i = 0; i < state->users->n; i++) {
			pace++;
			pace->e_tag = ACL_USER;
			pace->e_uid = state->users->aces[i].uid;
			pace->e_perm = state->users->aces[i].perms.allow;
		}

		pace++;
		pace->e_tag = ACL_GROUP_OBJ;
		pace->e_perm = state->group.allow;

		for (i = 0; i < state->groups->n; i++) {
			pace++;
			pace->e_tag = ACL_GROUP;
			pace->e_gid = state->users->aces[i].gid;
			pace->e_perm = state->users->aces[i].perms.allow;
		}

		if (state->users->n || state->groups->n) {
			pace++;
			pace->e_tag = ACL_MASK;
			pace->e_perm = state->mask.allow;
		}

		pace++;
		pace->e_tag = ACL_OTHER;
		pace->e_perm = state->other.allow;
}

static int init_acl_state(struct posix_acl_state *state, int cnt)
{
	int alloc;

	memset(state, 0, sizeof(struct posix_acl_state));
	state->empty = 1;
	/*
	 * In the worst case, each individual acl could be for a distinct
	 * named user or group, but we don't know which, so we allocate
	 * enough space for either:
	 */
	alloc = sizeof(struct posix_ace_state_array)
		+ cnt*sizeof(struct posix_user_ace_state);
	state->users = kzalloc(alloc, GFP_KERNEL);
	if (!state->users)
		return -ENOMEM;
	state->groups = kzalloc(alloc, GFP_KERNEL);
	if (!state->groups) {
		kfree(state->users);
		return -ENOMEM;
	}
	return 0;
}

static void parse_dacl(struct smb_acl *pdacl, char *end_of_acl,
		struct smb_sid *pownersid, struct smb_sid *pgrpsid,
		struct smb_fattr *fattr)
{
	int i, ret;
	int num_aces = 0;
	int acl_size;
	char *acl_base;
	struct smb_ace **ppace;
	struct posix_acl_entry *cf_pace, *cf_pdace;
	struct posix_acl_state acl_state, default_acl_state;
	umode_t mode;

	/* BB need to add parm so we can store the SID BB */

	if (!pdacl)
		return;

	/* validate that we do not go past end of acl */
	if (end_of_acl < (char *)pdacl + le16_to_cpu(pdacl->size)) {
		ksmbd_err("ACL too small to parse DACL\n");
		return;
	}

	ksmbd_debug(SMB, "DACL revision %d size %d num aces %d\n",
		 le16_to_cpu(pdacl->revision), le16_to_cpu(pdacl->size),
		 le32_to_cpu(pdacl->num_aces));

	acl_base = (char *)pdacl;
	acl_size = sizeof(struct smb_acl);

	num_aces = le32_to_cpu(pdacl->num_aces);
	if (num_aces > 0) {
		if (num_aces > ULONG_MAX / sizeof(struct smb_ace *))
			return;
		ppace = kmalloc_array(num_aces, sizeof(struct smb_ace *),
				      GFP_KERNEL);
		if (!ppace)
			return;

		ret = init_acl_state(&acl_state, num_aces);
		if (ret)
			return;
		ret = init_acl_state(&default_acl_state, num_aces);
		if (ret)
			return;

		/* set owner group */
		acl_state.owner.allow = fattr->cf_mode;
		acl_state.group.allow = fattr->cf_mode;
		acl_state.other.allow = fattr->cf_mode;

		default_acl_state.owner.allow = fattr->cf_mode;
		default_acl_state.group.allow = 0;
		default_acl_state.other.allow = 0;

		/*
		 * reset rwx permissions for user/group/other.
		 * Also, if num_aces is 0 i.e. DACL has no ACEs,
		 * user/group/other have no permissions
		 */
		fattr->cf_mode &= ~(0777);

		for (i = 0; i < num_aces; ++i) {
			ppace[i] = (struct smb_ace *) (acl_base + acl_size);

			if ((compare_sids(&(ppace[i]->sid),
					  &sid_unix_NFS_mode) == 0)) {
				fattr->cf_mode =
					le32_to_cpu(ppace[i]->sid.sub_auth[2]);
				break;
			} else if (!compare_sids(&(ppace[i]->sid), pownersid)) {
				mode = access_flags_to_mode(ppace[i]->access_req,
						     ppace[i]->type);
				acl_state.owner.allow = mode & 0007;
				acl_state.users->aces[acl_state.users->n].uid = fattr->cf_uid;
				acl_state.users->aces[acl_state.users->n++].perms.allow = mode & 0007;

				/* default acl */
				default_acl_state.owner.allow = mode & 0007;
				default_acl_state.users->aces[default_acl_state.users->n].uid = fattr->cf_uid;
				default_acl_state.users->aces[default_acl_state.users->n++].perms.allow = mode & 0007;
				mode &= 0007;
			} else if (!compare_sids(&(ppace[i]->sid), pgrpsid)) {
				mode = access_flags_to_mode(ppace[i]->access_req,
						     ppace[i]->type);
				acl_state.group.allow = mode & 0070;
				acl_state.groups->aces[acl_state.groups->n].gid = fattr->cf_gid;
				acl_state.groups->aces[acl_state.groups->n++].perms.allow = mode & 0070;

				/* default acl */
				default_acl_state.groups->aces[default_acl_state.groups->n].gid = fattr->cf_gid;
				default_acl_state.groups->aces[default_acl_state.groups->n++].perms.allow = 0;
				mode &= 0070;
			} else if (!compare_sids(&(ppace[i]->sid), &sid_everyone)) {
				mode = access_flags_to_mode(ppace[i]->access_req,
						ppace[i]->type);
				acl_state.other.allow = mode & 0007;
				mode &= 0007;
			} else {
				struct smb_fattr temp_fattr;

				mode = access_flags_to_mode(ppace[i]->access_req,
						     ppace[i]->type);
				ret = sid_to_id(&ppace[i]->sid, SIDOWNER, &temp_fattr);
				if (ret) {
					ksmbd_err("%s: Error %d mapping Owner SID to uid\n",
							__func__, ret);
				} else {
				acl_state.owner.allow = mode & 0007;
				acl_state.users->aces[acl_state.users->n].uid = temp_fattr.cf_uid;
				acl_state.users->aces[acl_state.users->n++].perms.allow = mode & 0007;

				/* default acl */
				default_acl_state.owner.allow = mode & 0007;
				default_acl_state.users->aces[default_acl_state.users->n].uid = temp_fattr.cf_uid;
				default_acl_state.users->aces[default_acl_state.users->n++].perms.allow = mode & 0007;
				}
			}

			fattr->cf_mode |= mode;

			acl_base = (char *)ppace[i];
			acl_size = le16_to_cpu(ppace[i]->size);
		}

		if (acl_state.users->n || acl_state.users->n)
			acl_state.mask.allow = 0x07;

		if (default_acl_state.users->n || default_acl_state.users->n)
			default_acl_state.mask.allow = 0x07;

		kfree(ppace);

		/*
		 * When there are no effective ACEs, the following will end
		 * up setting a 3-element effective posix ACL with all
		 * permissions zero.
		 */
		if (!acl_state.users->n && !acl_state.groups->n)
			num_aces = 3;
		else /* Note we also include a MASK ACE in this case: */
			num_aces = 4 + acl_state.users->n + acl_state.groups->n;

		fattr->cf_acls = posix_acl_alloc(num_aces, GFP_KERNEL);
		if (!fattr->cf_acls)
			return;

		fattr->cf_dacls = posix_acl_alloc(num_aces, GFP_KERNEL);
		if (!fattr->cf_dacls)
			return;

		cf_pace = fattr->cf_acls->a_entries;
		cf_pdace = fattr->cf_dacls->a_entries;

		posix_state_to_acl(&acl_state, cf_pace);
		posix_state_to_acl(&default_acl_state, cf_pdace);
	}
}

/*
 * Fill in the special SID based on the mode. See
 * http://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */
static unsigned int setup_special_mode_ACE(struct smb_ace *pntace, umode_t mode)
{
	int i;
	unsigned int ace_size = 28;

	pntace->type = ACCESS_DENIED_ACE_TYPE;
	pntace->flags = 0x0;
	pntace->access_req = 0;
	pntace->sid.num_subauth = 3;
	pntace->sid.revision = 1;
	for (i = 0; i < NUM_AUTHS; i++)
		pntace->sid.authority[i] = sid_unix_NFS_mode.authority[i];

	pntace->sid.sub_auth[0] = sid_unix_NFS_mode.sub_auth[0];
	pntace->sid.sub_auth[1] = sid_unix_NFS_mode.sub_auth[1];
	pntace->sid.sub_auth[2] = cpu_to_le32(mode);

	/* size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (psid->num_subauth*4) */
	pntace->size = cpu_to_le16(ace_size);
	return ace_size;
}

static void set_dacl(struct smb_acl *pndacl, const struct smb_sid *pownersid,
		const struct smb_sid *pgrpsid, struct smb_fattr *fattr)
{
	u16 size = 0;
	u32 num_aces = 0;
	struct smb_acl *pnndacl;
	struct smb_ace *pntace;
	umode_t mode = fattr->cf_mode;
	struct posix_acl_entry *pace;
	struct smb_sid *sid;
	int i;
	int flags = 0;

	pnndacl = (struct smb_acl *)((char *)pndacl + sizeof(struct smb_acl));
#if 0
	pntace = (struct smb_ace *)((char *)pnndacl + size);
	size += setup_special_mode_ACE(pntace, mode);
	num_aces++;
#endif
	size += fill_ace_for_sid((struct smb_ace *) ((char *)pnndacl + size),
					pownersid, flags, mode, 0700);
	num_aces++;
	size += fill_ace_for_sid((struct smb_ace *)((char *)pnndacl + size),
					pgrpsid, flags, mode, 0070);
	num_aces++;
	size += fill_ace_for_sid((struct smb_ace *)((char *)pnndacl + size),
					 &sid_everyone, flags, mode, 0007);
	num_aces++;
	
	if (!fattr->cf_acls || IS_ERR(fattr->cf_acls))
		goto out;

	pace = fattr->cf_acls->a_entries;
	for (i = 0; i < fattr->cf_acls->a_count; i++, pace++) {
		sid = kmalloc(sizeof(struct smb_sid), GFP_KERNEL);
		if (!sid)
			break;

		if (pace->e_tag == ACL_USER) {
			uid_t uid;

			uid = from_kuid(&init_user_ns, pace->e_uid);
			id_to_sid(uid, SIDOWNER, sid);
		} else if (pace->e_tag == ACL_GROUP) {
			gid_t gid;

			gid = from_kgid(&init_user_ns, pace->e_gid);
			id_to_sid(gid, SIDGROUP, sid);
		} else
			continue;

		if (fattr->cf_dacls)
			flags = 0x03;

		size += fill_ace_for_sid(
			(struct smb_ace *) ((char *)pnndacl + size),
				sid, flags, pace->e_perm, 0777);
		num_aces++;
		kfree(sid);
	}

	if (!fattr->cf_dacls || IS_ERR(fattr->cf_dacls))
		goto out;

	flags = 0x0b;
	pace = fattr->cf_dacls->a_entries;
	for (i = 0; i < fattr->cf_acls->a_count; i++, pace++) {
		sid = kmalloc(sizeof(struct smb_sid), GFP_KERNEL);
		if (!sid)
			break;

		if (pace->e_tag == ACL_USER) {
			uid_t uid;

			uid = from_kuid(&init_user_ns, pace->e_uid);
			id_to_sid(uid, SIDCREATOR_OWNER, sid);
		} else if (pace->e_tag == ACL_GROUP) {
			gid_t gid;

			gid = from_kgid(&init_user_ns, pace->e_gid);
			id_to_sid(gid, SIDCREATOR_GROUP, sid);
		} else if (pace->e_tag == ACL_OTHER) {

			smb_copy_sid(sid, &sid_everyone);
		} else
			continue;

		size += fill_ace_for_sid(
			(struct smb_ace *) ((char *)pnndacl + size),
				sid, flags, pace->e_perm, 0777);
		num_aces++;
		kfree(sid);
	}

out:
	pndacl->num_aces = cpu_to_le32(num_aces);
	pndacl->size = cpu_to_le16(size + sizeof(struct smb_acl));
}

static int parse_sid(struct smb_sid *psid, char *end_of_acl)
{
	/* BB need to add parm so we can store the SID BB */

	/* validate that we do not go past end of ACL - sid must be at least 8
	 *            bytes long (assuming no sub-auths - e.g. the null SID */
	if (end_of_acl < (char *)psid + 8) {
		ksmbd_err("ACL too small to parse SID %p\n", psid);
		return -EINVAL;
	}

#if 0//def //CONFIG_CIFS_DEBUG2
	if (psid->num_subauth) {
		int i;
		cifs_dbg(FYI, "SID revision %d num_auth %d\n",
				psid->revision, psid->num_subauth);

		for (i = 0; i < psid->num_subauth; i++) {
			cifs_dbg(FYI, "SID sub_auth[%d]: 0x%x\n",
					i, le32_to_cpu(psid->sub_auth[i]));
		}

		/* BB add length check to make sure that we do not have huge
		 *                         num auths and therefore go off the end */
		cifs_dbg(FYI, "RID 0x%x\n",
				le32_to_cpu(psid->sub_auth[psid->num_subauth-1]));
	}
#endif

	return 0;
}

/* Convert CIFS ACL to POSIX form */
int parse_sec_desc(struct smb_ntsd *pntsd, int acl_len,
		struct smb_fattr *fattr)
{
	int rc = 0;
	struct smb_sid *owner_sid_ptr, *group_sid_ptr;
	struct smb_acl *dacl_ptr; /* no need for SACL ptr */
	char *end_of_acl = ((char *)pntsd) + acl_len;
	__u32 dacloffset;

	if (pntsd == NULL)
		return -EIO;

	owner_sid_ptr = (struct smb_sid *)((char *)pntsd +
			le32_to_cpu(pntsd->osidoffset));
	group_sid_ptr = (struct smb_sid *)((char *)pntsd +
			le32_to_cpu(pntsd->gsidoffset));
	dacloffset = le32_to_cpu(pntsd->dacloffset);
	dacl_ptr = (struct smb_acl *)((char *)pntsd + dacloffset);
	ksmbd_debug(SMB,
		"revision %d type 0x%x ooffset 0x%x goffset 0x%x sacloffset 0x%x dacloffset 0x%x\n",
		 pntsd->revision, pntsd->type, le32_to_cpu(pntsd->osidoffset),
		 le32_to_cpu(pntsd->gsidoffset),
		 le32_to_cpu(pntsd->sacloffset), dacloffset);

	rc = parse_sid(owner_sid_ptr, end_of_acl);
	if (rc) {
		ksmbd_err("%s: Error %d parsing Owner SID\n", __func__, rc);
		return rc;
	}
	rc = sid_to_id(owner_sid_ptr, SIDOWNER, fattr);
	if (rc) {
		ksmbd_err("%s: Error %d mapping Owner SID to uid\n",
				__func__, rc);
		return rc;
	}

	rc = parse_sid(group_sid_ptr, end_of_acl);
	if (rc) {
		ksmbd_err("%s: Error %d mapping Owner SID to gid\n",
				__func__, rc);
		return rc;
	}
	rc = sid_to_id(group_sid_ptr, SIDGROUP, fattr);
	if (rc) {
		ksmbd_err("%s: Error %d mapping Group SID to gid\n",
				__func__, rc);
		return rc;
	}

	if (dacloffset)
		parse_dacl(dacl_ptr, end_of_acl, owner_sid_ptr, group_sid_ptr,
			fattr);
	else
		ksmbd_err("no ACL\n"); /* BB grant all or default perms? */

	if (pntsd->type & DACL_AUTO_INHERITED) {
		ksmbd_err("contain auto inherit!!\n");
	}

	return rc;
}

/* Convert permission bits from mode to equivalent CIFS ACL */
int build_sec_desc(struct smb_ntsd *pntsd, int addition_info, __u32 *secdesclen,
		struct smb_fattr *fattr)
{
	int rc = 0;
	__u32 offset;
	struct smb_sid *owner_sid_ptr, *group_sid_ptr;
	struct smb_sid *nowner_sid_ptr, *ngroup_sid_ptr;
	struct smb_acl *dacl_ptr = NULL; /* no need for SACL ptr */
	uid_t uid;
	gid_t gid;

	nowner_sid_ptr = kmalloc(sizeof(struct smb_sid), GFP_KERNEL);
	if (!nowner_sid_ptr)
		return -ENOMEM;

	uid = from_kuid(&init_user_ns, fattr->cf_uid);
	id_to_sid(uid, SIDOWNER, nowner_sid_ptr);

	ngroup_sid_ptr = kmalloc(sizeof(struct smb_sid), GFP_KERNEL);
	if (!ngroup_sid_ptr) {
		kfree(nowner_sid_ptr);
		return -ENOMEM;
	}

	gid = from_kgid(&init_user_ns, fattr->cf_gid);
	id_to_sid(gid, SIDGROUP, ngroup_sid_ptr);

	offset = sizeof(struct smb_ntsd);
	pntsd->sacloffset = 0;
	pntsd->type = ACCESS_ALLOWED;
	pntsd->revision = cpu_to_le16(1);
	pntsd->type = DACL_PROTECTED | SELF_RELATIVE;

	if (addition_info == DACL_SECINFO) { 
		dacl_ptr = (struct smb_acl *)((char *)pntsd + offset);
		dacl_ptr->revision = cpu_to_le16(2);
		dacl_ptr->size = 0;
		dacl_ptr->num_aces = 0;
		pntsd->type |= DACL_PRESENT;
		set_dacl(dacl_ptr, nowner_sid_ptr, ngroup_sid_ptr, fattr);
		pntsd->dacloffset = cpu_to_le32(offset);
		offset += le16_to_cpu(dacl_ptr->size);
	}

	if (addition_info == OWNER_SECINFO) {
		pntsd->osidoffset = cpu_to_le32(offset);
		owner_sid_ptr = (struct smb_sid *)((char *)pntsd + offset);
		smb_copy_sid(owner_sid_ptr, nowner_sid_ptr);
		offset += sizeof(struct smb_sid);
	}

	if (addition_info == GROUP_SECINFO) {
		pntsd->gsidoffset = cpu_to_le32(offset);
		group_sid_ptr = (struct smb_sid *)((char *)pntsd + offset);
		smb_copy_sid(group_sid_ptr, ngroup_sid_ptr);
		offset += sizeof(struct smb_sid);
	}

	*secdesclen = offset;
	return rc;
}
