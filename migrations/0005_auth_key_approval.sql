-- Device approval queue: keys can require that enrolled devices be approved by
-- an admin before they join the mesh.
ALTER TABLE auth_keys
    ADD COLUMN require_approval BOOLEAN NOT NULL DEFAULT false;
