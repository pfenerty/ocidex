-- +goose Up
CREATE FUNCTION sbom_visible(reg_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR reg_id IS NULL
      OR EXISTS (
           SELECT 1 FROM registry
           WHERE id = reg_id
             AND (visibility = 'public' OR owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;

-- +goose Down
DROP FUNCTION IF EXISTS sbom_visible;
