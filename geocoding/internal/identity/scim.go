package identity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SCIM provisioning store (docs/auth.md "SCIM 2.0"). Every method takes the
// org ID of the authenticated SCIM token and scopes every query to it, so a
// token can never read or change another org's users or groups.

// SCIM-specific errors. Handlers map them to SCIM 400 responses.
var (
	// ErrSCIMDomain: the email's domain is not a verified domain of the org.
	ErrSCIMDomain = errors.New("email domain is not a verified domain of this org")
	// ErrSCIMShared: the change would alter a user record shared with other
	// orgs (or a platform admin), which one org's IdP may not do.
	ErrSCIMShared = errors.New("user belongs to other orgs; userName cannot be changed by this org")
	// ErrSCIMMember: a group member is not a SCIM user of this org.
	ErrSCIMMember = errors.New("group member is not a provisioned user of this org")
)

// SCIMUser is a user provisioned into an org by SCIM. Data is the
// round-trip JSON owned by the scim package; the store treats it as opaque.
type SCIMUser struct {
	OrgID      int64
	UserID     int64
	SCIMID     string
	ExternalID string
	Active     bool
	Data       string
	Email      string
	Created    time.Time
	Updated    time.Time
}

// SCIMUserInput is the writable state of a SCIM user.
type SCIMUserInput struct {
	Email      string
	Name       string // display name for users.name when the user is ours alone
	ExternalID string
	Active     bool
	Data       string
}

// SCIMMember is a group member: the user's SCIM ID and email.
type SCIMMember struct {
	SCIMID string
	Email  string
}

// SCIMGroup is an IdP group pushed by SCIM.
type SCIMGroup struct {
	ID          int64
	OrgID       int64
	SCIMID      string
	ExternalID  string
	DisplayName string
	Created     time.Time
	Updated     time.Time
	Members     []SCIMMember // nil unless requested
}

// SCIMCond is a parsed SCIM filter. Op is "and", "or" or "eq". For "eq",
// Attr is one of the SCIMAttr constants; unknown attributes are rejected.
type SCIMCond struct {
	Op    string
	Attr  string
	Value string
	Sub   []SCIMCond
}

// Filterable attributes.
const (
	SCIMAttrID          = "id"
	SCIMAttrUserName    = "userName"
	SCIMAttrExternalID  = "externalId"
	SCIMAttrEmail       = "emails.value"
	SCIMAttrWorkEmail   = "emails.work.value"
	SCIMAttrDisplayName = "displayName"
)

const maxCondNodes = 50

// NewSCIMID returns a random RFC 4122 version 4 UUID.
func NewSCIMID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func compileCond(c SCIMCond, cols map[string]func(v string) (string, []any), n *int) (string, []any, error) {
	*n++
	if *n > maxCondNodes {
		return "", nil, ErrInvalid
	}
	switch c.Op {
	case "and", "or":
		if len(c.Sub) == 0 {
			return "", nil, ErrInvalid
		}
		var parts []string
		var args []any
		for _, sc := range c.Sub {
			q, a, err := compileCond(sc, cols, n)
			if err != nil {
				return "", nil, err
			}
			parts = append(parts, "("+q+")")
			args = append(args, a...)
		}
		return strings.Join(parts, " "+strings.ToUpper(c.Op)+" "), args, nil
	case "eq":
		f, ok := cols[c.Attr]
		if !ok {
			return "", nil, ErrInvalid
		}
		q, a := f(c.Value)
		return q, a, nil
	}
	return "", nil, ErrInvalid
}

var scimUserCols = map[string]func(string) (string, []any){
	SCIMAttrID:         func(v string) (string, []any) { return `s.scim_id = ?`, []any{v} },
	SCIMAttrUserName:   func(v string) (string, []any) { return `u.email = ?`, []any{NormaliseEmail(v)} },
	SCIMAttrExternalID: func(v string) (string, []any) { return `s.external_id = ?`, []any{v} },
	SCIMAttrEmail: func(v string) (string, []any) {
		return `u.email = ? OR EXISTS (SELECT 1 FROM json_each(s.data, '$.emails') e WHERE lower(json_extract(e.value, '$.value')) = ?)`,
			[]any{NormaliseEmail(v), NormaliseEmail(v)}
	},
	SCIMAttrWorkEmail: func(v string) (string, []any) {
		return `EXISTS (SELECT 1 FROM json_each(s.data, '$.emails') e WHERE lower(json_extract(e.value, '$.type')) = 'work' AND lower(json_extract(e.value, '$.value')) = ?)
			OR (COALESCE(json_array_length(s.data, '$.emails'), 0) = 0 AND u.email = ?)`, []any{NormaliseEmail(v), NormaliseEmail(v)}
	},
}

var scimGroupCols = map[string]func(string) (string, []any){
	SCIMAttrID:          func(v string) (string, []any) { return `g.scim_id = ?`, []any{v} },
	SCIMAttrExternalID:  func(v string) (string, []any) { return `g.external_id = ?`, []any{v} },
	SCIMAttrDisplayName: func(v string) (string, []any) { return `g.display_name = ?`, []any{v} },
}

// --- users ---

const scimUserSelect = `SELECT s.org_id, s.user_id, s.scim_id, s.external_id, s.active, s.data, u.email, s.created, s.updated
	FROM scim_users s JOIN users u ON u.id=s.user_id`

func scanSCIMUser(sc interface{ Scan(...any) error }) (SCIMUser, error) {
	var su SCIMUser
	var active int
	var c, up string
	if err := sc.Scan(&su.OrgID, &su.UserID, &su.SCIMID, &su.ExternalID, &active, &su.Data, &su.Email, &c, &up); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return su, ErrNotFound
		}
		return su, err
	}
	su.Active, su.Created, su.Updated = active != 0, parseTS(c), parseTS(up)
	return su, nil
}

// SCIMUserByID returns an org's SCIM user by SCIM ID.
func (s *Store) SCIMUserByID(ctx context.Context, orgID int64, scimID string) (SCIMUser, error) {
	return scanSCIMUser(s.db.QueryRowContext(ctx, scimUserSelect+` WHERE s.org_id=? AND s.scim_id=?`, orgID, scimID))
}

// SCIMUsers lists an org's SCIM users matching cond (nil = all), returning
// one page and the total match count.
func (s *Store) SCIMUsers(ctx context.Context, orgID int64, cond *SCIMCond, offset, limit int) ([]SCIMUser, int, error) {
	where, args := `s.org_id=?`, []any{orgID}
	if cond != nil {
		n := 0
		q, a, err := compileCond(*cond, scimUserCols, &n)
		if err != nil {
			return nil, 0, err
		}
		where += ` AND (` + q + `)`
		args = append(args, a...)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_users s JOIN users u ON u.id=s.user_id WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		return nil, total, nil
	}
	rows, err := s.db.QueryContext(ctx, scimUserSelect+` WHERE `+where+` ORDER BY s.rowid LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []SCIMUser
	for rows.Next() {
		su, err := scanSCIMUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, su)
	}
	return out, total, rows.Err()
}

func (s *Store) checkSCIMEmail(ctx context.Context, orgID int64, email string) (string, error) {
	email = NormaliseEmail(email)
	if !ValidEmail(email) {
		return "", ErrInvalid
	}
	if !s.orgHasVerifiedDomain(ctx, orgID, EmailDomain(email)) {
		return "", ErrSCIMDomain
	}
	return email, nil
}

// sharedUserTx reports whether a user's global record is shared beyond this
// org: a membership elsewhere, or platform admin.
func sharedUserTx(ctx context.Context, tx *sql.Tx, orgID, userID int64) (bool, error) {
	var n, admin int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM memberships WHERE user_id=? AND org_id<>?), platform_admin FROM users WHERE id=?`,
		userID, orgID, userID).Scan(&n, &admin); err != nil {
		return false, err
	}
	return n > 0 || admin != 0, nil
}

// CreateSCIMUser provisions a user into an org. An existing user with the
// email is linked; one already provisioned in this org is ErrConflict. The
// email's domain must be verified by the org.
func (s *Store) CreateSCIMUser(ctx context.Context, orgID int64, in SCIMUserInput) (SCIMUser, error) {
	email, err := s.checkSCIMEmail(ctx, orgID, in.Email)
	if err != nil {
		return SCIMUser{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SCIMUser{}, err
	}
	defer tx.Rollback()
	var uid int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE email=?`, email).Scan(&uid)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `INSERT INTO users(email, name, created) VALUES (?,?,?)`, email, trimName(in.Name), now())
		if err != nil {
			return SCIMUser{}, err
		}
		uid, _ = res.LastInsertId()
	case err != nil:
		return SCIMUser{}, err
	default:
		shared, err := sharedUserTx(ctx, tx, orgID, uid)
		if err != nil {
			return SCIMUser{}, err
		}
		if !shared && trimName(in.Name) != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET name=? WHERE id=?`, trimName(in.Name), uid); err != nil {
				return SCIMUser{}, err
			}
		}
	}
	scimID := NewSCIMID()
	t := now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO scim_users(org_id, user_id, scim_id, external_id, active, data, created, updated) VALUES (?,?,?,?,?,?,?,?)`,
		orgID, uid, scimID, in.ExternalID, b2i(in.Active), dataOr(in.Data), t, t); err != nil {
		if isUnique(err) {
			return SCIMUser{}, ErrConflict
		}
		return SCIMUser{}, err
	}
	if in.Active {
		if err := scimActivateTx(ctx, tx, orgID, uid); err != nil {
			return SCIMUser{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return SCIMUser{}, err
	}
	return s.SCIMUserByID(ctx, orgID, scimID)
}

// ReplaceSCIMUser sets a SCIM user's full state. Deactivating removes the
// org membership and the user's sessions (and deprovisions a user left with
// no orgs); activating restores the membership. changed reports an
// activation change: +1 reactivated, -1 deactivated, 0 none.
func (s *Store) ReplaceSCIMUser(ctx context.Context, orgID int64, scimID string, in SCIMUserInput) (su SCIMUser, changed int, err error) {
	email := NormaliseEmail(in.Email)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return su, 0, err
	}
	defer tx.Rollback()
	cur, err := scanSCIMUser(tx.QueryRowContext(ctx, scimUserSelect+` WHERE s.org_id=? AND s.scim_id=?`, orgID, scimID))
	if err != nil {
		return su, 0, err
	}
	shared, err := sharedUserTx(ctx, tx, orgID, cur.UserID)
	if err != nil {
		return su, 0, err
	}
	if email != cur.Email {
		// Only a new address is checked against verified domains, so an
		// org that drops a domain can still deactivate its users.
		if _, err := s.checkSCIMEmail(ctx, orgID, email); err != nil {
			return su, 0, err
		}
		if shared {
			return su, 0, ErrSCIMShared
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET email=? WHERE id=?`, email, cur.UserID); err != nil {
			if isUnique(err) {
				return su, 0, ErrConflict
			}
			return su, 0, err
		}
	}
	if !shared && trimName(in.Name) != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET name=? WHERE id=?`, trimName(in.Name), cur.UserID); err != nil {
			return su, 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scim_users SET external_id=?, active=?, data=?, updated=? WHERE org_id=? AND user_id=?`,
		in.ExternalID, b2i(in.Active), dataOr(in.Data), now(), orgID, cur.UserID); err != nil {
		return su, 0, err
	}
	switch {
	case in.Active && !cur.Active:
		changed = 1
		err = scimActivateTx(ctx, tx, orgID, cur.UserID)
	case !in.Active && cur.Active:
		changed = -1
		err = scimDeactivateTx(ctx, tx, orgID, cur.UserID)
	}
	if err != nil {
		return su, 0, err
	}
	if err := tx.Commit(); err != nil {
		return su, 0, err
	}
	su, err = s.SCIMUserByID(ctx, orgID, scimID)
	return su, changed, err
}

// DeleteSCIMUser unlinks a SCIM user: removes the scim_users row, the user's
// SCIM group memberships in the org and the org membership, and deletes
// sessions. The global user row stays (it may belong to other orgs).
func (s *Store) DeleteSCIMUser(ctx context.Context, orgID int64, scimID string) (SCIMUser, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SCIMUser{}, err
	}
	defer tx.Rollback()
	cur, err := scanSCIMUser(tx.QueryRowContext(ctx, scimUserSelect+` WHERE s.org_id=? AND s.scim_id=?`, orgID, scimID))
	if err != nil {
		return cur, err
	}
	if err := scimDeactivateTx(ctx, tx, orgID, cur.UserID); err != nil {
		return cur, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_members WHERE user_id=? AND group_id IN (SELECT id FROM scim_groups WHERE org_id=?)`, cur.UserID, orgID); err != nil {
		return cur, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scim_users WHERE org_id=? AND user_id=?`, orgID, cur.UserID); err != nil {
		return cur, err
	}
	return cur, tx.Commit()
}

// scimActivateTx gives the user an org membership (role from SCIM group
// mappings, else the org default) if they have none, and reactivates a
// deprovisioned user. An existing membership is left alone.
func scimActivateTx(ctx context.Context, tx *sql.Tx, orgID, userID int64) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		role, err := scimRoleTx(ctx, tx, orgID, userID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO memberships(org_id, user_id, role, source, created) VALUES (?,?,?,?,?)`,
			orgID, userID, role.String(), SourceSCIM, now()); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE users SET status=? WHERE id=? AND status=?`, StatusActive, userID, StatusDeprovisioned)
	return err
}

// scimDeactivateTx removes the org membership (any source; the last owner is
// protected), deletes the user's sessions and deprovisions a user left with
// no memberships who is not a platform admin.
func scimDeactivateTx(ctx context.Context, tx *sql.Tx, orgID, userID int64) error {
	var cur string
	err := tx.QueryRowContext(ctx, `SELECT role FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&cur)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	default:
		if ParseRole(cur) == RoleOwner {
			if err := ensureAnotherOwner(ctx, tx, orgID, userID); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET status=? WHERE id=? AND platform_admin=0
		AND NOT EXISTS (SELECT 1 FROM memberships WHERE user_id=?)`, StatusDeprovisioned, userID, userID)
	return err
}

// scimRoleTx is the role SCIM group mappings give a user in an org: the
// highest mapped role of the SCIM groups they are in, else the default role.
func scimRoleTx(ctx context.Context, tx *sql.Tx, orgID, userID int64) (Role, error) {
	rows, err := tx.QueryContext(ctx, `SELECT m.role FROM group_mappings m
		JOIN scim_groups g ON g.org_id=m.org_id AND g.display_name=m.grp
		JOIN scim_group_members gm ON gm.group_id=g.id
		WHERE m.org_id=? AND m.source='scim' AND gm.user_id=?`, orgID, userID)
	if err != nil {
		return RoleNone, err
	}
	best := RoleNone
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return RoleNone, err
		}
		if pr := ParseRole(r); pr > best {
			best = pr
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return RoleNone, err
	}
	if best != RoleNone {
		return best, nil
	}
	var def string
	if err := tx.QueryRowContext(ctx, `SELECT default_role FROM orgs WHERE id=?`, orgID).Scan(&def); err != nil {
		return RoleNone, err
	}
	if r := ParseRole(def); r != RoleNone {
		return r, nil
	}
	return RoleViewer, nil
}

// scimRecomputeTx re-derives the role of a SCIM-sourced membership from SCIM
// groups. Memberships from any other source (manual, invite, ...) are never
// touched; demoting the last owner fails with ErrLastOwner.
func scimRecomputeTx(ctx context.Context, tx *sql.Tx, orgID, userID int64) error {
	var cur, source string
	err := tx.QueryRowContext(ctx, `SELECT role, source FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&cur, &source)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if source != SourceSCIM {
		return nil
	}
	role, err := scimRoleTx(ctx, tx, orgID, userID)
	if err != nil {
		return err
	}
	old := ParseRole(cur)
	if role == old {
		return nil
	}
	if old == RoleOwner {
		if err := ensureAnotherOwner(ctx, tx, orgID, userID); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE memberships SET role=? WHERE org_id=? AND user_id=?`, role.String(), orgID, userID)
	return err
}

// --- groups ---

const scimGroupSelect = `SELECT g.id, g.org_id, g.scim_id, g.external_id, g.display_name, g.created, g.updated FROM scim_groups g`

func scanSCIMGroup(sc interface{ Scan(...any) error }) (SCIMGroup, error) {
	var g SCIMGroup
	var c, u string
	if err := sc.Scan(&g.ID, &g.OrgID, &g.SCIMID, &g.ExternalID, &g.DisplayName, &c, &u); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return g, ErrNotFound
		}
		return g, err
	}
	g.Created, g.Updated = parseTS(c), parseTS(u)
	return g, nil
}

type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}

func scimGroupMembers(ctx context.Context, q querier, groupID int64) ([]SCIMMember, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.scim_id, u.email FROM scim_group_members gm
		JOIN scim_groups g ON g.id=gm.group_id
		JOIN scim_users s ON s.org_id=g.org_id AND s.user_id=gm.user_id
		JOIN users u ON u.id=gm.user_id
		WHERE gm.group_id=? ORDER BY u.email`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SCIMMember{}
	for rows.Next() {
		var m SCIMMember
		if err := rows.Scan(&m.SCIMID, &m.Email); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SCIMGroupByID returns an org's group, with members if asked.
func (s *Store) SCIMGroupByID(ctx context.Context, orgID int64, scimID string, members bool) (SCIMGroup, error) {
	g, err := scanSCIMGroup(s.db.QueryRowContext(ctx, scimGroupSelect+` WHERE g.org_id=? AND g.scim_id=?`, orgID, scimID))
	if err != nil || !members {
		return g, err
	}
	g.Members, err = scimGroupMembers(ctx, s.db, g.ID)
	return g, err
}

// SCIMGroups lists an org's groups matching cond (nil = all), returning one
// page and the total match count.
func (s *Store) SCIMGroups(ctx context.Context, orgID int64, cond *SCIMCond, offset, limit int, members bool) ([]SCIMGroup, int, error) {
	where, args := `g.org_id=?`, []any{orgID}
	if cond != nil {
		n := 0
		q, a, err := compileCond(*cond, scimGroupCols, &n)
		if err != nil {
			return nil, 0, err
		}
		where += ` AND (` + q + `)`
		args = append(args, a...)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_groups g WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		return nil, total, nil
	}
	rows, err := s.db.QueryContext(ctx, scimGroupSelect+` WHERE `+where+` ORDER BY g.id LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	var out []SCIMGroup
	for rows.Next() {
		g, err := scanSCIMGroup(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if members {
		for i := range out {
			if out[i].Members, err = scimGroupMembers(ctx, s.db, out[i].ID); err != nil {
				return nil, 0, err
			}
		}
	}
	return out, total, nil
}

// resolveMembersTx maps member SCIM IDs to user IDs within the org.
func resolveMembersTx(ctx context.Context, tx *sql.Tx, orgID int64, scimIDs []string) (map[int64]bool, error) {
	out := make(map[int64]bool, len(scimIDs))
	for _, id := range scimIDs {
		var uid int64
		err := tx.QueryRowContext(ctx, `SELECT user_id FROM scim_users WHERE org_id=? AND scim_id=?`, orgID, id).Scan(&uid)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSCIMMember
		}
		if err != nil {
			return nil, err
		}
		out[uid] = true
	}
	return out, nil
}

func validGroupName(n string) bool { return n != "" && len(n) <= 256 }

// CreateSCIMGroup creates a group with members (SCIM user IDs of this org)
// and recomputes the members' roles.
func (s *Store) CreateSCIMGroup(ctx context.Context, orgID int64, displayName, externalID string, members []string) (SCIMGroup, error) {
	displayName = strings.TrimSpace(displayName)
	if !validGroupName(displayName) {
		return SCIMGroup{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SCIMGroup{}, err
	}
	defer tx.Rollback()
	uids, err := resolveMembersTx(ctx, tx, orgID, members)
	if err != nil {
		return SCIMGroup{}, err
	}
	scimID, t := NewSCIMID(), now()
	res, err := tx.ExecContext(ctx, `INSERT INTO scim_groups(org_id, scim_id, external_id, display_name, created, updated) VALUES (?,?,?,?,?,?)`,
		orgID, scimID, externalID, displayName, t, t)
	if err != nil {
		if isUnique(err) {
			return SCIMGroup{}, ErrConflict
		}
		return SCIMGroup{}, err
	}
	gid, _ := res.LastInsertId()
	for uid := range uids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scim_group_members(group_id, user_id) VALUES (?,?)`, gid, uid); err != nil {
			return SCIMGroup{}, err
		}
		if err := scimRecomputeTx(ctx, tx, orgID, uid); err != nil {
			return SCIMGroup{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return SCIMGroup{}, err
	}
	return s.SCIMGroupByID(ctx, orgID, scimID, true)
}

// ReplaceSCIMGroup sets a group's name, external ID and full member list,
// then recomputes the role of every user whose groups changed (all members
// when the name changed, since mappings match on name).
func (s *Store) ReplaceSCIMGroup(ctx context.Context, orgID int64, scimID, displayName, externalID string, members []string) (SCIMGroup, error) {
	displayName = strings.TrimSpace(displayName)
	if !validGroupName(displayName) {
		return SCIMGroup{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SCIMGroup{}, err
	}
	defer tx.Rollback()
	g, err := scanSCIMGroup(tx.QueryRowContext(ctx, scimGroupSelect+` WHERE g.org_id=? AND g.scim_id=?`, orgID, scimID))
	if err != nil {
		return g, err
	}
	want, err := resolveMembersTx(ctx, tx, orgID, members)
	if err != nil {
		return g, err
	}
	have := map[int64]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT user_id FROM scim_group_members WHERE group_id=?`, g.ID)
	if err != nil {
		return g, err
	}
	for rows.Next() {
		var uid int64
		if err := rows.Scan(&uid); err != nil {
			rows.Close()
			return g, err
		}
		have[uid] = true
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `UPDATE scim_groups SET display_name=?, external_id=?, updated=? WHERE id=?`, displayName, externalID, now(), g.ID); err != nil {
		if isUnique(err) {
			return g, ErrConflict
		}
		return g, err
	}
	affected := map[int64]bool{}
	for uid := range have {
		if !want[uid] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_members WHERE group_id=? AND user_id=?`, g.ID, uid); err != nil {
				return g, err
			}
			affected[uid] = true
		} else if displayName != g.DisplayName {
			affected[uid] = true
		}
	}
	for uid := range want {
		if !have[uid] {
			if _, err := tx.ExecContext(ctx, `INSERT INTO scim_group_members(group_id, user_id) VALUES (?,?)`, g.ID, uid); err != nil {
				return g, err
			}
			affected[uid] = true
		}
	}
	for uid := range affected {
		if err := scimRecomputeTx(ctx, tx, orgID, uid); err != nil {
			return g, err
		}
	}
	if err := tx.Commit(); err != nil {
		return g, err
	}
	return s.SCIMGroupByID(ctx, orgID, scimID, true)
}

// DeleteSCIMGroup deletes a group and recomputes its former members' roles.
func (s *Store) DeleteSCIMGroup(ctx context.Context, orgID int64, scimID string) (SCIMGroup, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SCIMGroup{}, err
	}
	defer tx.Rollback()
	g, err := scanSCIMGroup(tx.QueryRowContext(ctx, scimGroupSelect+` WHERE g.org_id=? AND g.scim_id=?`, orgID, scimID))
	if err != nil {
		return g, err
	}
	var uids []int64
	rows, err := tx.QueryContext(ctx, `SELECT user_id FROM scim_group_members WHERE group_id=?`, g.ID)
	if err != nil {
		return g, err
	}
	for rows.Next() {
		var uid int64
		if err := rows.Scan(&uid); err != nil {
			rows.Close()
			return g, err
		}
		uids = append(uids, uid)
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `DELETE FROM scim_groups WHERE id=?`, g.ID); err != nil {
		return g, err
	}
	for _, uid := range uids {
		if err := scimRecomputeTx(ctx, tx, orgID, uid); err != nil {
			return g, err
		}
	}
	return g, tx.Commit()
}

func trimName(n string) string {
	n = strings.TrimSpace(n)
	if len(n) > 200 {
		n = n[:200]
	}
	return n
}

func dataOr(d string) string {
	if d == "" {
		return "{}"
	}
	return d
}
