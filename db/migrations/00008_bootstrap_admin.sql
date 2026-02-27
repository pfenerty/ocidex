-- +goose Up
INSERT INTO ocidex_user (github_id, github_username, role)
VALUES (16961380, 'pfenerty', 'admin')
ON CONFLICT (github_id) DO UPDATE SET role = 'admin';

-- +goose Down
DELETE FROM ocidex_user WHERE github_id = 16961380;
