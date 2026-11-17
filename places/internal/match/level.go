package match

import (
	"context"
	"database/sql"
	"sync"
)

// levelColumns records, per dataset, whether address has level_number. A
// dataset built before buildaddr added it serves as before, levels unread.
var levelColumns sync.Map // *sql.DB -> bool

// levelColumn is the SQL expression for an address row's level: the column,
// or an empty string on a dataset without it.
func levelColumn(ctx context.Context, db *sql.DB) string {
	has, ok := levelColumns.Load(db)
	if !ok {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('address')
			WHERE name = 'level_number'`).Scan(&n); err != nil {
			return `''` // not cached: a cancelled request must not decide for the dataset
		}
		has = n == 1
		levelColumns.Store(db, has)
	}
	if has.(bool) {
		return `a.level_number`
	}
	return `''`
}
