output "database_fqdn" {
  value = azurerm_postgresql_flexible_server.agent_roi.fqdn
}

output "database_secret_id" {
  value = azurerm_key_vault_secret.database.id
}

output "signing_key_id" {
  value = azurerm_key_vault_key.signing.id
}

output "key_vault_id" {
  value = azurerm_key_vault.agent_roi.id
}
