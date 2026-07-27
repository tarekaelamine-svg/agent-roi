CREATE TABLE IF NOT EXISTS scim_users (
    user_id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    active BOOLEAN NOT NULL,
    emails_json JSONB NOT NULL,
    attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    organization_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    UNIQUE (organization_id, user_name)
);
CREATE TABLE IF NOT EXISTS scim_groups (
    group_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    UNIQUE (organization_id, display_name)
);
CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY(group_id, user_id),
    FOREIGN KEY(group_id) REFERENCES scim_groups(group_id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES scim_users(user_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS rbac_roles (
    name TEXT PRIMARY KEY,
    permissions_json JSONB NOT NULL,
    description TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS rbac_bindings (
    binding_id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    group_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    FOREIGN KEY(role) REFERENCES rbac_roles(name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scim_users_org ON scim_users(organization_id, user_name);
CREATE INDEX IF NOT EXISTS idx_scim_groups_org ON scim_groups(organization_id, display_name);
CREATE INDEX IF NOT EXISTS idx_rbac_bindings_org ON rbac_bindings(organization_id, environment);
