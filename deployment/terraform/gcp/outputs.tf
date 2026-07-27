output "database_connection_name" {
  value = google_sql_database_instance.agent_roi.connection_name
}

output "database_secret_id" {
  value = google_secret_manager_secret.database.id
}

output "signing_key_id" {
  value = google_kms_crypto_key.signing.id
}
