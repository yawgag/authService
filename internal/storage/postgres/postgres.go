package postgres

import (
	"authService/internal/config"
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DBPool interface {
	Close()
	Begin(ctx context.Context) (Tx, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type Tx interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type PgxDBPool struct {
	pool *pgxpool.Pool
}
type PgxTx struct {
	tx pgx.Tx
}

func (p *PgxDBPool) Begin(ctx context.Context) (Tx, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &PgxTx{tx: tx}, nil
}

func (p *PgxDBPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return p.pool.QueryRow(ctx, sql, args...)
}

func (p *PgxDBPool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return p.pool.Query(ctx, sql, args...)
}

func (p *PgxDBPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return p.pool.Exec(ctx, sql, args...)
}

func (p *PgxDBPool) Close() {
	p.pool.Close()
}

func (p *PgxTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return p.tx.QueryRow(ctx, sql, args...)
}

func (p *PgxTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return p.tx.Exec(ctx, sql, args...)
}

func (p *PgxTx) Commit(ctx context.Context) error {
	return p.tx.Commit(ctx)
}

func (p *PgxTx) Rollback(ctx context.Context) error {
	return p.tx.Rollback(ctx)
}

func InitDb() (DBPool, error) {
	serverConfig, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	dbConfig, err := pgxpool.ParseConfig(serverConfig.DbURL)
	if err != nil {
		log.Fatal(err)
	}

	dbConfig.MaxConns = 20
	dbConfig.MinConns = 1
	dbConfig.MaxConnLifetime = time.Hour

	DbConnPool, err := pgxpool.NewWithConfig(context.Background(), dbConfig)
	if err != nil {
		log.Fatal(err)
	}

	err = DbConnPool.Ping(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	return &PgxDBPool{pool: DbConnPool}, err
}
