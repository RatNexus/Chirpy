// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: chirps.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const canBeDeleted = `-- name: CanBeDeleted :one
SELECT 1 FROM chirps
WHERE id = $1 AND user_id = $2
`

type CanBeDeletedParams struct {
	ID     uuid.UUID
	UserID uuid.UUID
}

func (q *Queries) CanBeDeleted(ctx context.Context, arg CanBeDeletedParams) (int32, error) {
	row := q.db.QueryRowContext(ctx, canBeDeleted, arg.ID, arg.UserID)
	var column_1 int32
	err := row.Scan(&column_1)
	return column_1, err
}

const createChirp = `-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(), NOW(), NOW(), $1, $2
)
RETURNING id, created_at, updated_at, body, user_id
`

type CreateChirpParams struct {
	Body   string
	UserID uuid.UUID
}

func (q *Queries) CreateChirp(ctx context.Context, arg CreateChirpParams) (Chirp, error) {
	row := q.db.QueryRowContext(ctx, createChirp, arg.Body, arg.UserID)
	var i Chirp
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Body,
		&i.UserID,
	)
	return i, err
}

const deleteChirp = `-- name: DeleteChirp :exec
DELETE FROM chirps
WHERE id = $1 AND user_id = $2
`

type DeleteChirpParams struct {
	ID     uuid.UUID
	UserID uuid.UUID
}

func (q *Queries) DeleteChirp(ctx context.Context, arg DeleteChirpParams) error {
	_, err := q.db.ExecContext(ctx, deleteChirp, arg.ID, arg.UserID)
	return err
}

const getAllChirps = `-- name: GetAllChirps :many
SELECT id, created_at, updated_at, body, user_id FROM chirps
ORDER BY created_at ASC
`

func (q *Queries) GetAllChirps(ctx context.Context) ([]Chirp, error) {
	rows, err := q.db.QueryContext(ctx, getAllChirps)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Chirp
	for rows.Next() {
		var i Chirp
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Body,
			&i.UserID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getChirp = `-- name: GetChirp :one
SELECT id, created_at, updated_at, body, user_id from chirps
WHERE id = $1
`

func (q *Queries) GetChirp(ctx context.Context, id uuid.UUID) (Chirp, error) {
	row := q.db.QueryRowContext(ctx, getChirp, id)
	var i Chirp
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Body,
		&i.UserID,
	)
	return i, err
}

const getUsersChirps = `-- name: GetUsersChirps :many
SELECT id, created_at, updated_at, body, user_id FROM chirps
WHERE user_id = $1
`

func (q *Queries) GetUsersChirps(ctx context.Context, userID uuid.UUID) ([]Chirp, error) {
	rows, err := q.db.QueryContext(ctx, getUsersChirps, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Chirp
	for rows.Next() {
		var i Chirp
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Body,
			&i.UserID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
