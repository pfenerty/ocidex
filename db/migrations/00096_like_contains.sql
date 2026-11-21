-- +goose Up
-- like_contains turns user search input into an ILIKE pattern that matches it
-- as a substring, literally. Without it, '%' || q || '%' let a search for
-- "foo_bar" match "fooXbar" and a search for "%" match everything, which also
-- forced a full scan on demand (ocidex-4zfn.1). Backslash is Postgres's
-- default LIKE escape character, so the patterns need no ESCAPE clause.
-- IMMUTABLE, so the planner folds it over a query parameter and trigram
-- indexes still apply.
-- +goose StatementBegin
CREATE FUNCTION like_contains(q TEXT) RETURNS TEXT
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT '%' || replace(replace(replace(q, '\', '\\'), '%', '\%'), '_', '\_') || '%'
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS like_contains(TEXT);
