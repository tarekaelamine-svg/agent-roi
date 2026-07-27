terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
  }
}

data "azurerm_client_config" "current" {}

resource "random_password" "database" {
  length           = 32
  special          = true
  override_special = "!#$%&*+-=?^_"
}

resource "azurerm_key_vault" "agent_roi" {
  name                       = replace("${var.name}-kv", "_", "-")
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "premium"
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
  enable_rbac_authorization  = true
}

resource "azurerm_role_assignment" "current_principal_crypto" {
  scope                = azurerm_key_vault.agent_roi.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "current_principal_secrets" {
  scope                = azurerm_key_vault.agent_roi.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_key" "signing" {
  name         = "policy-signing"
  key_vault_id = azurerm_key_vault.agent_roi.id
  key_type     = "RSA-HSM"
  key_size     = 3072
  key_opts     = ["sign", "verify"]

  depends_on = [azurerm_role_assignment.current_principal_crypto]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P365D"
    notify_before_expiry = "P60D"
  }
}

resource "azurerm_postgresql_flexible_server" "agent_roi" {
  name                   = replace("${var.name}-postgres", "_", "-")
  resource_group_name    = var.resource_group_name
  location               = var.location
  version                = "16"
  delegated_subnet_id    = var.subnet_id
  administrator_login    = var.administrator_login
  administrator_password = random_password.database.result
  storage_mb             = 32768
  sku_name               = "GP_Standard_D2s_v3"
  backup_retention_days  = 14
  geo_redundant_backup_enabled = true

  authentication {
    password_auth_enabled         = true
    active_directory_auth_enabled = true
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }
}

resource "azurerm_postgresql_flexible_server_database" "agent_roi" {
  name      = var.database_name
  server_id = azurerm_postgresql_flexible_server.agent_roi.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_key_vault_secret" "database" {
  name         = "postgres-dsn"
  depends_on   = [azurerm_role_assignment.current_principal_secrets]
  key_vault_id = azurerm_key_vault.agent_roi.id
  value = format(
    "postgresql://%s:%s@%s:5432/%s?sslmode=require",
    var.administrator_login,
    urlencode(random_password.database.result),
    azurerm_postgresql_flexible_server.agent_roi.fqdn,
    var.database_name,
  )
}
