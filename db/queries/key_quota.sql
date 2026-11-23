-- name: ConsumeKeyQuota :one
-- Counts one action against the key's budget for this hour and returns the
-- new total. Atomic under concurrency: the upsert serializes on the row.
INSERT INTO key_quota_window (api_key_id, class, window_start, used)
VALUES (@api_key_id, @class, date_trunc('hour', now()), 1)
ON CONFLICT (api_key_id, class, window_start)
DO UPDATE SET used = key_quota_window.used + 1
RETURNING used;

-- name: PruneKeyQuotaWindows :exec
DELETE FROM key_quota_window
WHERE api_key_id = @api_key_id AND window_start < date_trunc('hour', now());

-- name: RefundKeyQuota :exec
-- Gives back an action counted for a request that was then refused: a request
-- that did nothing should not spend the budget.
UPDATE key_quota_window SET used = used - 1
WHERE api_key_id = @api_key_id AND class = @class AND window_start = date_trunc('hour', now()) AND used > 0;
