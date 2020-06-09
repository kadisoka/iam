package iamserver

import (
	"github.com/jmoiron/sqlx"
)

func doTx(db *sqlx.DB, txFunc func(*sqlx.Tx) error) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	defer func() {
		if rec := recover(); rec != nil {
			tx.Rollback()
			panic(rec)
		} else if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()
	err = txFunc(tx)
	return err
}
