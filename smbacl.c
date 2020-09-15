// SPDX-License-Identifier: LGPL-2.1+
/*
 *   Copyright (C) International Business Machines  Corp., 2007,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Copyright (C) 2020 Namjae Jeon <linkinjeon@kernel.org>
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "smbacl.h"
#include "smb_common.h"
#include "server.h"
#include "misc.h"

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
int
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
		ksmbd_debug(SMB, "all perms\n");
		return mode;
	}

	if ((flags & GENERIC_READ) ||
			(flags & FILE_READ_RIGHTS))
		mode = 0444;
	if ((flags & GENERIC_WRITE) ||
			(flags & FILE_WRITE_RIGHTS))
		mode |= 0222;
	if ((flags & GENERIC_EXECUTE) ||
			(flags & FILE_EXEC_RIGHTS))
		mode |= 0111;

	if (type == ACCESS_DENIED_ACE_TYPE || type == ACCESS_DENIED_OBJECT_ACE_TYPE)
	       mode = ~(mode);

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
		*pace_flags |= FILE_WRITE_RIGHTS;
	if (mode & 0111)
		*pace_flags |= SET_FILE_EXEC_RIGHTS;

	ksmbd_debug(SMB, "mode: 0x%o, access flags now 0x%x\n",
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

void id_to_sid(unsigned int cid, uint sidtype, struct smb_sid *ssid)
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
	int rc = -EINVAL;

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
		if (id > 0) {
			uid = make_kuid(&init_user_ns, id);
			if (uid_valid(uid) && kuid_has_mapping(&init_user_ns, uid)) {
				fattr->cf_uid = uid;
				rc = 0;
			}
		}
	} else {
		kgid_t gid;
		gid_t id;
		
		id = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);
		if (id > 0) {
			gid = make_kgid(&init_user_ns, id);
			if (gid_valid(gid) && kgid_has_mapping(&init_user_ns, gid)) {
				fattr->cf_gid = gid;
				rc = 0;
			}
		}
	}

	return rc;
}

void posix_state_to_acl(struct posix_acl_state *state, struct posix_acl_entry *pace)
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
			pace->e_perm = state->groups->aces[i].perms.allow;
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

int init_acl_state(struct posix_acl_state *state, int cnt)
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

void free_acl_state(struct posix_acl_state *state)
{
	kfree(state->users);
	kfree(state->groups);
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
	umode_t mode = 0, acl_mode;
	struct smb_ace *ace;
	bool owner_found = false, group_found = false, others_found = false;

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
	fattr->ntacl->size = le16_to_cpu(pdacl->size);

	num_aces = le32_to_cpu(pdacl->num_aces);
	if (num_aces <= 0)
		return;

	if (num_aces > ULONG_MAX / sizeof(struct smb_ace *))
		return;

	fattr->ntacl->num_aces = num_aces;
	ppace = kmalloc_array(num_aces, sizeof(struct smb_ace *),
			GFP_KERNEL);
	if (!ppace)
		return;

	ret = init_acl_state(&acl_state, num_aces);
	if (ret)
		return;
	ret = init_acl_state(&default_acl_state, num_aces);
	if (ret) {
		free_acl_state(&acl_state);
		return;
	}

	/*
	 * reset rwx permissions for user/group/other.
	 * Also, if num_aces is 0 i.e. DACL has no ACEs,
	 * user/group/other have no permissions
	 */
	ace = fattr->ntacl->ace;
	for (i = 0; i < num_aces; ++i) {
		ppace[i] = (struct smb_ace *) (acl_base + acl_size);

		memcpy(ace, ppace[i], ppace[i]->size);
		ace->access_req = smb_map_generic_desired_access(ppace[i]->access_req);
		if (!(compare_sids(&(ppace[i]->sid), &sid_unix_NFS_mode))) {
			fattr->cf_mode =
				le32_to_cpu(ppace[i]->sid.sub_auth[2]);
			break;
		} else if (!compare_sids(&(ppace[i]->sid), pownersid)) {
			acl_mode = access_flags_to_mode(ppace[i]->access_req,
					ppace[i]->type);
			fattr->daccess = ace->access_req;
			acl_mode &= 0700;

			if ((fattr->cf_mode & 0700) != acl_mode || !owner_found) {
				mode &= ~(0700);
				mode |= acl_mode;
			}
			owner_found = true;
		} else if (!compare_sids(&(ppace[i]->sid), pgrpsid) ||
				le32_to_cpu(ppace[i]->sid.sub_auth[ppace[i]->sid.num_subauth - 1]) == 513) {
			acl_mode = access_flags_to_mode(ppace[i]->access_req,
					ppace[i]->type);
			acl_mode &= 0070;
			if ((fattr->cf_mode & 0070) != acl_mode || !group_found) {
				mode &= ~(0070);
				mode |= acl_mode;
			}
			group_found = true;
		} else if (!compare_sids(&(ppace[i]->sid), &sid_everyone)) {
			acl_mode = access_flags_to_mode(ppace[i]->access_req,
					ppace[i]->type);
			acl_mode &= 0007;
			if ((fattr->cf_mode & 0007) != acl_mode || !others_found) {
				mode &= ~(0007);
				mode |= acl_mode;
			}
			others_found = true;
		} else if (!compare_sids(&(ppace[i]->sid), &creator_owner)) {
			goto skip;
		} else if (!compare_sids(&(ppace[i]->sid), &creator_group)) {
			goto skip;
		} else if (!compare_sids(&(ppace[i]->sid), &sid_authusers)) {
			goto skip;
		} else {
			struct smb_fattr temp_fattr;

			acl_mode = access_flags_to_mode(ppace[i]->access_req,
					ppace[i]->type);
			temp_fattr.cf_uid = INVALID_UID;
			ret = sid_to_id(&ppace[i]->sid, SIDOWNER, &temp_fattr);
			if (ret || uid_eq(temp_fattr.cf_uid, INVALID_UID)) {
				ksmbd_err("%s: Error %d mapping Owner SID to uid\n",
						__func__, ret);
				goto skip;
			} else {
				fattr->daccess = ace->access_req;
				acl_state.users->aces[acl_state.users->n].uid = temp_fattr.cf_uid;
				acl_state.users->aces[acl_state.users->n++].perms.allow = acl_mode & 0700 >> 6;
				ksmbd_err("user!\n");
			}
		}

skip:
		acl_base = (char *)ppace[i];
		acl_size = le16_to_cpu(ppace[i]->size);
		ace = (struct smb_ace *)((char *)ace + ppace[i]->size);
	}
	kfree(ppace);

	if (owner_found) {
		fattr->cf_mode &= ~(0700);
		fattr->cf_mode |= mode & 0700;

		/* The owner must be set to at least read-only. */
		acl_state.owner.allow = ((mode & 0700) >> 6) | 0004;
		acl_state.users->aces[acl_state.users->n].uid = fattr->cf_uid;
		acl_state.users->aces[acl_state.users->n++].perms.allow = (mode & 0700) >> 6;
		default_acl_state.owner.allow = mode & 0700 >> 6;
		default_acl_state.users->aces[default_acl_state.users->n].uid = fattr->cf_uid;
		default_acl_state.users->aces[default_acl_state.users->n++].perms.allow = (mode & 0700) >> 6;
	}

	if (group_found) {
		fattr->cf_mode &= ~(0070);
		fattr->cf_mode |= mode & 0070;

		acl_state.group.allow = (mode & 0070) >> 3;
		acl_state.groups->aces[acl_state.groups->n].gid = fattr->cf_gid;
		acl_state.groups->aces[acl_state.groups->n++].perms.allow = (mode & 0070) >> 3;
		default_acl_state.groups->aces[default_acl_state.groups->n].gid = fattr->cf_gid;
		default_acl_state.groups->aces[default_acl_state.groups->n++].perms.allow = (mode & 0070) >> 3;
	}

	if (others_found) {
		fattr->cf_mode &= ~(0007);
		fattr->cf_mode |= mode & 0007;

		acl_state.other.allow = mode & 0007;
		default_acl_state.other.allow = mode & 0007;
	}
	if (acl_state.users->n || acl_state.groups->n) {
		acl_state.mask.allow = 0x07;
		fattr->cf_acls = posix_acl_alloc(4 + acl_state.users->n + acl_state.groups->n, GFP_KERNEL);
		if (fattr->cf_acls) {
			cf_pace = fattr->cf_acls->a_entries;
			posix_state_to_acl(&acl_state, cf_pace);
		}
		free_acl_state(&acl_state);
	}

	if (default_acl_state.users->n || default_acl_state.groups->n) {
		default_acl_state.mask.allow = 0x07;
		fattr->cf_dacls = posix_acl_alloc(4 + default_acl_state.users->n + default_acl_state.groups->n,
				GFP_KERNEL);
		if (fattr->cf_dacls) {
			cf_pdace = fattr->cf_dacls->a_entries;
			posix_state_to_acl(&default_acl_state, cf_pdace);
		}
		free_acl_state(&default_acl_state);
	}
}

static void set_dacl(struct smb_acl *pndacl, const struct smb_sid *pownersid,
		const struct smb_sid *pgrpsid, struct smb_fattr *fattr)
{
	u16 size = 0;
	u32 num_aces = 0;
	struct smb_acl *pnndacl;
	struct posix_acl_entry *pace;
	struct smb_sid *sid;
	int i;
	int flags = 0;

	pnndacl = (struct smb_acl *)((char *)pndacl + sizeof(struct smb_acl));

	if (fattr->ntacl->num_aces) {
		struct smb_ace *ace;

		ace = fattr->ntacl->ace;
		for (i = 0; i < fattr->ntacl->num_aces; i++) {
			memcpy((char *)pnndacl + size, ace, ace->size);
			size += ace->size;
			ace = (struct smb_ace *)((char *)ace + ace->size);
			num_aces++;
		}

		goto out;
	}

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
		} else if (pace->e_tag == ACL_OTHER) {
			smb_copy_sid(sid, &sid_everyone);
		} else {
			kfree(sid);
			continue;
		}

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
	for (i = 0; i < fattr->cf_dacls->a_count; i++, pace++) {
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
		} else {
			kfree(sid);
			continue;
		}
		size += fill_ace_for_sid(
			(struct smb_ace *) ((char *)pnndacl + size),
				sid, flags, pace->e_perm, 0777);
		num_aces++;
		kfree(sid);
	}

out:
	pndacl->num_aces = cpu_to_le32(num_aces);
	pndacl->size += cpu_to_le16(size);
}

static void set_default_dacl(struct smb_acl *pndacl, struct smb_fattr *fattr)
{
	u16 size = 0;
	struct smb_acl *pnndacl;
	struct smb_ace *pace;
	int access_req = 0;

	pnndacl = (struct smb_acl *)((char *)pndacl + sizeof(struct smb_acl));
	pace = (struct smb_ace *)pnndacl;

	/* owner RID */
	pace->type = ACCESS_ALLOWED;
	pace->flags = 0;
	mode_to_access_flags(fattr->cf_mode, 0700, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	pace->access_req = access_req | FILE_DELETE_LE;

	smb_copy_sid(&pace->sid, &cifsd_domain);
	pace->sid.sub_auth[pace->sid.num_subauth] = from_kuid(&init_user_ns, fattr->cf_uid);
	pace->sid.num_subauth++;
	pace->size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (pace->sid.num_subauth * 4);
	size += pace->size;
	pace = (struct smb_ace *)((char *)pnndacl + size);

	/* Domain users */
	pace->type = ACCESS_ALLOWED;
	pace->flags = 0;
	mode_to_access_flags(fattr->cf_mode, 0070, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	pace->access_req = access_req;

	smb_copy_sid(&pace->sid, &cifsd_domain);
	pace->sid.sub_auth[pace->sid.num_subauth] = 513;
	pace->sid.num_subauth++;
	pace->size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (pace->sid.num_subauth * 4);
	size += pace->size;
	pace = (struct smb_ace *)((char *)pnndacl + size);

	/* other */
	pace->type = ACCESS_ALLOWED;
	pace->flags = 0;
	mode_to_access_flags(fattr->cf_mode, 0007, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	pace->access_req = access_req;
	smb_copy_sid(&pace->sid, &sid_everyone);
	pace->size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (pace->sid.num_subauth * 4);
	size += pace->size;

	if (S_ISDIR(fattr->cf_mode)) {
		pace = (struct smb_ace *)((char *)pnndacl + size);

		/* creator owner */
		pace->type = ACCESS_ALLOWED;
		pace->flags = 0x0b;
		mode_to_access_flags(fattr->cf_mode, 0700, &access_req);
		if (!access_req)
			access_req = SET_MINIMUM_RIGHTS;
		pace->access_req = access_req | FILE_DELETE_LE;

		smb_copy_sid(&pace->sid, &creator_owner);
		pace->size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (pace->sid.num_subauth * 4);
		size += pace->size;
		pace = (struct smb_ace *)((char *)pnndacl + size);

		/* creator group */
		pace->type = ACCESS_ALLOWED;
		pace->flags = 0x0b;
		mode_to_access_flags(fattr->cf_mode, 0070, &access_req);
		if (!access_req)
			access_req = SET_MINIMUM_RIGHTS;
		pace->access_req = access_req;

		smb_copy_sid(&pace->sid, &creator_group);
		pace->size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (pace->sid.num_subauth * 4);
		size += pace->size;
		pace = (struct smb_ace *)((char *)pnndacl + size);

		/* other */
		pace->type = ACCESS_ALLOWED;
		pace->flags = 0x0b;
		mode_to_access_flags(fattr->cf_mode, 0007, &access_req);
		if (!access_req)
			access_req = SET_MINIMUM_RIGHTS;
		pace->access_req = access_req;
		smb_copy_sid(&pace->sid, &sid_everyone);
		pace->size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (pace->sid.num_subauth * 4);
		size += pace->size;

		pndacl->num_aces = cpu_to_le32(6);
	} else
		pndacl->num_aces = cpu_to_le32(3);
	pndacl->size += cpu_to_le16(size);
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
	int total_ace_size = 0;

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

	if (dacloffset && dacl_ptr)
		total_ace_size = le16_to_cpu(dacl_ptr->size) - sizeof(struct smb_acl);
	fattr->ntacl = kzalloc(sizeof(struct smb_ntacl) +
			total_ace_size, GFP_KERNEL);
	if (!fattr->ntacl)
		return -ENOMEM;

	if (!(le16_to_cpu(pntsd->type) & DACL_PRESENT)) {
		ksmbd_debug(SMB, "DACL_PRESENT in DACL type is not set\n");
		return rc;
	}

	fattr->ntacl->type = DACL_PRESENT;

	if (pntsd->osidoffset) {
		rc = parse_sid(owner_sid_ptr, end_of_acl);
		if (rc) {
			ksmbd_err("%s: Error %d parsing Owner SID\n", __func__, rc);
			return rc;
		}

		rc= sid_to_id(owner_sid_ptr, SIDOWNER, fattr);
		if (rc) {
			ksmbd_err("%s: Error %d mapping Owner SID to uid\n",
					__func__, rc);
			owner_sid_ptr = NULL;
		}
	}

	if (pntsd->gsidoffset) {
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
			group_sid_ptr = NULL;
		}
	}

	if ((le16_to_cpu(pntsd->type) & (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ)) ==
			(DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ))
		fattr->ntacl->type |= DACL_AUTO_INHERITED;
	fattr->ntacl->type |= le16_to_cpu(pntsd->type) & DACL_PROTECTED;

	if (dacloffset) {
		parse_dacl(dacl_ptr, end_of_acl, owner_sid_ptr, group_sid_ptr,
				fattr);
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
	pntsd->type = SELF_RELATIVE;
	if (fattr->ntacl)
		pntsd->type |= cpu_to_le16(fattr->ntacl->type);

	if (addition_info & OWNER_SECINFO) {
		pntsd->osidoffset = cpu_to_le32(offset);
		owner_sid_ptr = (struct smb_sid *)((char *)pntsd + offset);
		smb_copy_sid(owner_sid_ptr, nowner_sid_ptr);
		offset += 1 + 1 + 6 + (nowner_sid_ptr->num_subauth * 4);
	}

	if (addition_info & GROUP_SECINFO) {
		pntsd->gsidoffset = cpu_to_le32(offset);
		group_sid_ptr = (struct smb_sid *)((char *)pntsd + offset);
		smb_copy_sid(group_sid_ptr, ngroup_sid_ptr);
		offset += 1 + 1 + 6 + (ngroup_sid_ptr->num_subauth * 4);
	}

	if (addition_info & DACL_SECINFO) {
		pntsd->type |= DACL_PRESENT;
		dacl_ptr = (struct smb_acl *)((char *)pntsd + offset);
		dacl_ptr->revision = cpu_to_le16(2);
		dacl_ptr->size = cpu_to_le16(sizeof(struct smb_acl));
		dacl_ptr->num_aces = 0;

		if (!fattr->ntacl)
			set_default_dacl(dacl_ptr, fattr);
		else if (!fattr->ntacl->size)
			goto out;
		else
			set_dacl(dacl_ptr, nowner_sid_ptr, ngroup_sid_ptr, fattr);

		pntsd->dacloffset = cpu_to_le32(offset);
		offset += le16_to_cpu(dacl_ptr->size);
	}

out:
	kfree(nowner_sid_ptr);
	kfree(ngroup_sid_ptr);
	*secdesclen = offset;
	return rc;
}

static void smb_set_ace(struct smb_ace *ace, const struct smb_sid *sid, u8 type,
		u8 flags, __le32 access_req)
{
	ace->type = type;
	ace->flags = flags;
	ace->access_req = access_req;
	smb_copy_sid(&ace->sid, sid);
	ace->size = 1 + 1 + 2 + 4 + 1 + 1 + 6 + (sid->num_subauth * 4);
}

int smb_inherit_acls(struct smb_fattr *fattr, struct dentry *parent,
		bool is_dir, unsigned int uid, unsigned int gid)
{
	const struct smb_sid *psid, *creator = NULL;
	struct smb_ace *paces, *aces;
	struct smb_ntacl *pntacl;
	struct smb_sid owner_sid, group_sid;
	int inherited_flags = 0, flags = 0, i, ace_cnt = 0, nt_size = 0;
	char *aces_base;
	int rc = -ENOENT;

	pntacl = ksmbd_vfs_get_sd_xattr(parent);
	if (!pntacl)
		return rc;

	if (!pntacl->num_aces)
		goto free_pntacl;

	aces_base = kmalloc(sizeof(struct smb_ace) * pntacl->num_aces * 2,
			GFP_KERNEL);
	if (!aces_base)
		goto free_pntacl;

	aces = (struct smb_ace *)aces_base;
	paces = pntacl->ace;

	if (pntacl->type & DACL_AUTO_INHERITED)
		inherited_flags = INHERITED_ACE;

	for (i = 0; i < pntacl->num_aces; i++) {
		flags = paces->flags;
		if (!smb_inherit_flags(paces->flags, is_dir))
			continue;
		if (is_dir) {
			flags &= ~(INHERIT_ONLY_ACE | INHERITED_ACE);
			if (!(flags & CONTAINER_INHERIT_ACE))
				flags |= INHERIT_ONLY_ACE;
			if (flags & NO_PROPAGATE_INHERIT_ACE)
				flags = 0;
		} else
			flags = 0;

		if (paces->type & DACL_AUTO_INHERITED)
			flags |= INHERITED_ACE;

		if (!compare_sids(&creator_owner, &paces->sid)) {
			creator = &creator_owner;
			id_to_sid(uid, SIDOWNER, &owner_sid);
			psid = &owner_sid;
		} else if (!compare_sids(&creator_group, &paces->sid)) {
			creator = &creator_group;
			id_to_sid(gid, SIDGROUP, &group_sid);
			psid = &group_sid;
		} else {
			creator = NULL;
			psid = &paces->sid;
		}

		if (is_dir && creator && flags & CONTAINER_INHERIT_ACE) {
			smb_set_ace(aces, psid, paces->type, inherited_flags,
					paces->access_req);
			nt_size += aces->size;
			ace_cnt++;
			aces = (struct smb_ace *)((char *)aces + aces->size);
			flags |= INHERIT_ONLY_ACE;
			psid = creator;
		} else if (is_dir && !(paces->flags & NO_PROPAGATE_INHERIT_ACE))
			psid = &paces->sid;

		smb_set_ace(aces, psid, paces->type, flags | inherited_flags,
				paces->access_req);
		nt_size += aces->size;
		aces = (struct smb_ace *)((char *)aces + aces->size);
		ace_cnt++;
		paces = (struct smb_ace *)((char *)paces + paces->size);
	}

	if (nt_size > 0) {
		fattr->ntacl = kmalloc(sizeof(struct smb_ntacl) + nt_size,
				GFP_KERNEL);
		if (!fattr->ntacl)
			return -ENOMEM;
		fattr->ntacl->num_aces = ace_cnt;
		fattr->ntacl->type = SELF_RELATIVE | DACL_PRESENT; 
		if (pntacl->type & DACL_AUTO_INHERITED)
			fattr->ntacl->type |= DACL_AUTO_INHERITED;
		fattr->ntacl->size = nt_size;

		memcpy(fattr->ntacl->ace, aces_base, nt_size);
		rc = 0;
	}

	kfree(aces_base);
free_pntacl:
	kfree(pntacl);

	return rc;
}

int smb_set_default_ntacl(struct smb_fattr *fattr)
{
	struct smb_ace *pace;
	__u32 access_req;
	char *pace_base;
	int num_aces;
       
	fattr->ntacl = kmalloc(sizeof(struct smb_ntacl) + 3 * sizeof(struct smb_ace),
			GFP_KERNEL);
	if (!fattr->ntacl)
		return -ENOMEM;

	if (S_ISDIR(fattr->cf_mode))
		num_aces = 6;
	else
		num_aces = 3;

	fattr->ntacl->num_aces = num_aces;

	pace_base = kmalloc_array(num_aces, sizeof(struct smb_ace),
			GFP_KERNEL);
	if (!pace_base)
		return -ENOMEM;

	/* owner RID */
	pace = (struct smb_ace *)pace_base;
	mode_to_access_flags(fattr->cf_mode, 0700, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	smb_set_ace(pace, &cifsd_domain, ACCESS_ALLOWED, 0, access_req | FILE_DELETE_LE);
	pace->sid.sub_auth[pace->sid.num_subauth++] = from_kuid(&init_user_ns, fattr->cf_uid);
	/* Increase RID size */
	pace->size += 4;
	fattr->ntacl->size = pace->size;

	/* Domain users */
	pace = (struct smb_ace *)((char *)pace + pace->size);
	mode_to_access_flags(fattr->cf_mode, 0070, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	smb_set_ace(pace, &cifsd_domain, ACCESS_ALLOWED, 0, access_req); 
	pace->sid.sub_auth[pace->sid.num_subauth++] = 513;
	/* Increase RID size */
	pace->size += 4;
	fattr->ntacl->size += pace->size;

	/* other */
	pace = (struct smb_ace *)((char *)pace + pace->size);
	mode_to_access_flags(fattr->cf_mode, 0007, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	smb_set_ace(pace, &sid_everyone, ACCESS_ALLOWED, 0, access_req);
	fattr->ntacl->size += pace->size;

	if (S_ISDIR(fattr->cf_mode)) {
		/* creator owner */
		pace = (struct smb_ace *)((char *)pace + pace->size);
		mode_to_access_flags(fattr->cf_mode, 0700, &access_req);
		if (!access_req)
			access_req = SET_MINIMUM_RIGHTS;
		smb_set_ace(pace, &creator_owner, ACCESS_ALLOWED, 0x0b, access_req);
		fattr->ntacl->size += pace->size;

		/* creator group */
		pace = (struct smb_ace *)((char *)pace + pace->size);
		mode_to_access_flags(fattr->cf_mode, 0070, &access_req);
		if (!access_req)
			access_req = SET_MINIMUM_RIGHTS;
		smb_set_ace(pace, &creator_group, ACCESS_ALLOWED, 0x0b, access_req);
		fattr->ntacl->size += pace->size;

		/* other */
		pace = (struct smb_ace *)((char *)pace + pace->size);
		mode_to_access_flags(fattr->cf_mode, 0007, &access_req);
		if (!access_req)
			access_req = SET_MINIMUM_RIGHTS;
		smb_set_ace(pace, &sid_everyone, ACCESS_ALLOWED, 0x0b, access_req);
		fattr->ntacl->size += pace->size;
	}

	memcpy(fattr->ntacl->ace, pace_base, fattr->ntacl->size);
	fattr->ntacl->type = SELF_RELATIVE | DACL_PRESENT;
	return 0;
}

int smb_set_default_posix_acl(struct inode *inode)
{
	struct posix_acl_state acl_state;
	struct posix_acl *acls;
	int rc;

	ksmbd_debug(SMB, "Set posix acls\n");
	init_acl_state(&acl_state, 1);

	/* Set default owner group */
	acl_state.owner.allow = (inode->i_mode & 0700) >> 6;
	acl_state.group.allow = (inode->i_mode & 0070) >> 3;
	acl_state.other.allow = inode->i_mode & 0007;
	acl_state.users->aces[acl_state.users->n].uid = inode->i_uid;
	acl_state.users->aces[acl_state.users->n++].perms.allow = acl_state.owner.allow;
	acl_state.groups->aces[acl_state.groups->n].gid = inode->i_gid;
	acl_state.groups->aces[acl_state.groups->n++].perms.allow = acl_state.group.allow;
	acl_state.mask.allow = 0x07;

	acls = posix_acl_alloc(6, GFP_KERNEL);
	if (!acls)
		return -ENOMEM;
	posix_state_to_acl(&acl_state, acls->a_entries);
	rc = ksmbd_vfs_set_posix_acl(inode, ACL_TYPE_ACCESS, acls);
	if (rc < 0)
		ksmbd_err("Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",
				rc);
	else if (S_ISDIR(inode->i_mode)) {
		acl_state.group.allow = 0;
		acl_state.other.allow = 0;
		acl_state.users->aces[0].perms.allow = 0;
		acl_state.groups->aces[0].perms.allow = 0;
		posix_state_to_acl(&acl_state, acls->a_entries);
		rc = ksmbd_vfs_set_posix_acl(inode, ACL_TYPE_DEFAULT, acls);
		if (rc < 0)
			ksmbd_err("Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",
					rc);
	}
	free_acl_state(&acl_state);
	posix_acl_release(acls);
	return rc;
}

bool smb_inherit_flags(int flags, bool is_dir)
{
	if (!is_dir)
		return (flags & OBJECT_INHERIT_ACE) != 0;

	if (flags & OBJECT_INHERIT_ACE && !(flags & NO_PROPAGATE_INHERIT_ACE))
		return true;

	if (flags & CONTAINER_INHERIT_ACE)
			return true;
	return false;
}

int smb_check_perm_ntacl(struct dentry *dentry, __le32 *pdaccess, int uid)
{
	struct smb_ntacl *ntacl;
	int rc = 0;
	struct smb_sid sid;
	int granted = (*pdaccess & ~FILE_MAXIMAL_ACCESS_LE);
	struct smb_ace *ace;
	int i, found = 0;
	__le32 access_bits = 0;
	struct smb_ace *others_ace = NULL;

	ksmbd_debug(SMB, "check permission using windows acl\n");
	ntacl = ksmbd_vfs_get_sd_xattr(dentry);
	if (!ntacl)
		return 0;

	if (!ntacl->num_aces) {
		if (ntacl->size > 0 &&
		    *pdaccess & ~(FILE_READ_CONTROL_LE | FILE_WRITE_DAC_LE)) {
			rc = -EACCES;
			goto err_out;
		}
		return 0;
	}

	if (*pdaccess & FILE_MAXIMAL_ACCESS_LE) {
		for (i = 0; i < ntacl->num_aces; i++)
			granted |= ntacl->ace[i].access_req;

		if (!ntacl->num_aces)
			granted = GENERIC_ALL_FLAGS;
	}

	id_to_sid(uid, SIDOWNER, &sid);

	ace = ntacl->ace;
	// check permission of fp dacesss with each ondisk dcal aces
	for (i = 0; i < ntacl->num_aces; i++) {
		if (!compare_sids(&sid, &ace->sid)) {
			found = 1;
			break;
		}
		if (!compare_sids(&sid_everyone, &ace->sid))
			others_ace = ace;

		ace = (struct smb_ace *) ((char *)ace + ace->size);
	}

	if (!found) {
		if (others_ace)
			ace = others_ace;
		else {
			ksmbd_debug(SMB, "Can't find corresponding sid\n");
			rc = -EACCES;
			goto err_out;
		}
	}

	switch (ace->type) {
	case ACCESS_ALLOWED_ACE_TYPE:
		access_bits = ace->access_req;
		break;
	case ACCESS_DENIED_ACE_TYPE:
	case ACCESS_DENIED_CALLBACK_ACE_TYPE:
		access_bits = ~ace->access_req;
		break;
	}

	if (granted & ~(access_bits | FILE_READ_ATTRIBUTES_LE |
		FILE_READ_CONTROL_LE)) {
		ksmbd_debug(SMB, "Access denied with winACL, granted : %x, access_req : %x\n",
				granted, ace->access_req);
		rc = -EACCES;
		goto err_out;
	}

	*pdaccess |= granted;

err_out:
	kfree(ntacl);

	return rc;
}
