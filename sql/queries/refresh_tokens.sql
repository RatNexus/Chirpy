-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    token, created_at, updated_at, expires_at, revoked_at, user_id
) VALUES (
    $2, NOW(), NOW(), NOW() + INTERVAL '60 days', NULL, $1
)
RETURNING *;

-- name: GetRefreshToken :one
SELECT user_id FROM refresh_tokens
WHERE token = $1 AND revoked_at IS NULL;

-- name: RevokeToken :one
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE token = $1
RETURNING user_id;
