// SPDX-License-Identifier: LGPL-2.1+
/*
 *   Copyright (C) International Business Machines  Corp., 2007,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Modified by Namjae Jeon <linkinjeon@kernel.org>
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "smbacl.h"
#include "smb_common.h"
#include "server.h"

static const struct smb_sid cifsd_domain = {1, 4, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(21),
	 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

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
static void access_flags_to_mode(__le32 ace_flags, int type, umode_t *pmode,
				 umode_t *pbits_to_set)
{
	__u32 flags = le32_to_cpu(ace_flags);
	/*
	 * the order of ACEs is important.  The canonical order is to begin with
	 * DENY entries followed by ALLOW, otherwise an allow entry could be
	 * encountered first, making the subsequent deny entry like "dead code"
	 * which would be superfluous since Windows stops when a match is made
	 * for the operation you are trying to perform for your user
	 */

	/*
	 * For deny ACEs we change the mask so that subsequent allow access
	 * control entries do not turn on the bits we are denying
	 */
	if (type == ACCESS_DENIED) {
		if (flags & GENERIC_ALL)
			*pbits_to_set &= ~0777;

		if ((flags & GENERIC_WRITE) ||
			((flags & FILE_WRITE_RIGHTS) == FILE_WRITE_RIGHTS))
			*pbits_to_set &= ~0222;
		if ((flags & GENERIC_READ) ||
			((flags & FILE_READ_RIGHTS) == FILE_READ_RIGHTS))
			*pbits_to_set &= ~0444;
		if ((flags & GENERIC_EXECUTE) ||
			((flags & FILE_EXEC_RIGHTS) == FILE_EXEC_RIGHTS))
			*pbits_to_set &= ~0111;
		return;
	} else if (type != ACCESS_ALLOWED) {
		ksmbd_err("unknown access control type %d\n", type);
		return;
	}
	/* else ACCESS_ALLOWED type */

	if (flags & GENERIC_ALL) {
		*pmode |= (0777 & (*pbits_to_set));
		ksmbd_err("all perms\n");
		return;
	}
	if ((flags & GENERIC_WRITE) ||
			((flags & FILE_WRITE_RIGHTS) == FILE_WRITE_RIGHTS))
		*pmode |= (0222 & (*pbits_to_set));
	if ((flags & GENERIC_READ) ||
			((flags & FILE_READ_RIGHTS) == FILE_READ_RIGHTS))
		*pmode |= (0444 & (*pbits_to_set));
	if ((flags & GENERIC_EXECUTE) ||
			((flags & FILE_EXEC_RIGHTS) == FILE_EXEC_RIGHTS))
		*pmode |= (0111 & (*pbits_to_set));

	ksmbd_debug(SMB, "access flags 0x%x mode now %04o\n", flags, *pmode);
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
			const struct smb_sid *psid, umode_t mode, umode_t bits)
{
	int i;
	__u16 size = 0;
	__u32 access_req = 0;

	pntace->type = ACCESS_ALLOWED;
	pntace->flags = 0x0;
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

static void parse_dacl(struct smb_acl *pdacl, char *end_of_acl,
		struct smb_sid *pownersid, struct smb_sid *pgrpsid,
		struct smb_fattr *fattr)
{
	int i;
	int num_aces = 0;
	int acl_size;
	char *acl_base;
	struct smb_ace **ppace;

	/* BB need to add parm so we can store the SID BB */

	if (!pdacl) {
		/*
		 * no DACL in the security descriptor, set
		 * all the permissions for user/group/other
		 */
		fattr->cf_mode |= 0777;
		return;
	}

	/* validate that we do not go past end of acl */
	if (end_of_acl < (char *)pdacl + le16_to_cpu(pdacl->size)) {
		ksmbd_err("ACL too small to parse DACL\n");
		return;
	}

	ksmbd_debug(SMB, "DACL revision %d size %d num aces %d\n",
		 le16_to_cpu(pdacl->revision), le16_to_cpu(pdacl->size),
		 le32_to_cpu(pdacl->num_aces));

	/*
	 * reset rwx permissions for user/group/other.
	 * Also, if num_aces is 0 i.e. DACL has no ACEs,
	 * user/group/other have no permissions
	 */
	fattr->cf_mode &= ~(0777);

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

		for (i = 0; i < num_aces; ++i) {
			umode_t user_mask = 0700;
			umode_t group_mask = 0070;
			umode_t other_mask = 0777;

			ppace[i] = (struct smb_ace *) (acl_base + acl_size);
			if ((compare_sids(&(ppace[i]->sid),
					  &sid_unix_NFS_mode) == 0)) {
				fattr->cf_mode =
					le32_to_cpu(ppace[i]->sid.sub_auth[2]);
				break;
			} else if (!compare_sids(&(ppace[i]->sid), pownersid))
				access_flags_to_mode(ppace[i]->access_req,
						     ppace[i]->type,
						     &fattr->cf_mode,
						     &user_mask);
			else if (!compare_sids(&(ppace[i]->sid), pgrpsid))
				access_flags_to_mode(ppace[i]->access_req,
						     ppace[i]->type,
						     &fattr->cf_mode,
						     &group_mask);
			else if (!compare_sids(&(ppace[i]->sid), &sid_everyone))
				access_flags_to_mode(ppace[i]->access_req,
						     ppace[i]->type,
						     &fattr->cf_mode,
						     &other_mask);
			else if (!compare_sids(&(ppace[i]->sid),
					       &sid_authusers))
				access_flags_to_mode(ppace[i]->access_req,
						     ppace[i]->type,
						     &fattr->cf_mode,
						     &other_mask);

			acl_base = (char *)ppace[i];
			acl_size = le16_to_cpu(ppace[i]->size);
		}

		kfree(ppace);
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

static int set_chmod_dacl(struct smb_acl *pndacl,
		const struct smb_sid *pownersid,
		const struct smb_sid *pgrpsid, umode_t mode)
{
	u16 size = 0;
	u32 num_aces = 0;
	struct smb_acl *pnndacl;
	struct smb_ace *pntace;

	pnndacl = (struct smb_acl *)((char *)pndacl + sizeof(struct smb_acl));
	pntace = (struct smb_ace *)((char *)pnndacl + size);
	size += setup_special_mode_ACE(pntace, mode);
	num_aces++;

	size += fill_ace_for_sid((struct smb_ace *) ((char *)pnndacl + size),
					pownersid, mode, 0700);
	num_aces++;
	size += fill_ace_for_sid((struct smb_ace *)((char *)pnndacl + size),
					pgrpsid, mode, 0070);
	num_aces++;
	size += fill_ace_for_sid((struct smb_ace *)((char *)pnndacl + size),
					 &sid_everyone, mode, 0007);
	num_aces++;

	pndacl->num_aces = cpu_to_le32(num_aces);
	pndacl->size = cpu_to_le16(size + sizeof(struct smb_acl));

	return 0;
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

	return rc;
}

static void id_to_sid(unsigned int cid, uint sidtype, struct smb_sid *ssid)
{
	if (sidtype == SIDOWNER) {
		smb_copy_sid(ssid, &cifsd_domain);
	} else {
		/* sidtype == SIDGROUP */
		smb_copy_sid(ssid, &sid_unix_groups);
	}

	/* RID */
	ssid->sub_auth[ssid->num_subauth] = cid;
	ssid->num_subauth++;
}

/* Convert permission bits from mode to equivalent CIFS ACL */
int build_sec_desc(struct smb_ntsd *pntsd, __u32 *secdesclen,
		struct smb_fattr *fattr)
{
	int rc = 0;
	__u32 dacloffset;
	__u32 sidsoffset;
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

	owner_sid_ptr = (struct smb_sid *)((char *)pntsd + sidsoffset);
	smb_copy_sid(owner_sid_ptr, nowner_sid_ptr);

	/* copy group sid */
	group_sid_ptr = (struct smb_sid *)((char *)pntsd + sidsoffset +
					sizeof(struct smb_sid));
	smb_copy_sid(group_sid_ptr, ngroup_sid_ptr);

	dacloffset = sizeof(struct smb_ntsd);
	dacl_ptr = (struct smb_acl *)((char *)pntsd + dacloffset);
	dacl_ptr->revision = cpu_to_le16(1);
	dacl_ptr->size = 0;
	dacl_ptr->num_aces = 0;

	rc = set_chmod_dacl(dacl_ptr, owner_sid_ptr,
		group_sid_ptr, fattr->cf_mode);
	sidsoffset = dacloffset + le16_to_cpu(dacl_ptr->size);

	pntsd->osidoffset = cpu_to_le32(sidsoffset);
	pntsd->gsidoffset = cpu_to_le32(sidsoffset + sizeof(struct smb_sid));
	pntsd->dacloffset = cpu_to_le32(dacloffset);
	pntsd->sacloffset = 0;
	pntsd->type = ACCESS_ALLOWED;
	pntsd->revision = cpu_to_le16(1);

	*secdesclen = le32_to_cpu(pntsd->gsidoffset) + sizeof(struct smb_sid);
	return rc;
}
