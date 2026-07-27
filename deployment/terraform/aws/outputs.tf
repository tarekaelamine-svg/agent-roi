output "database_endpoint" {
  value = aws_rds_cluster.agent_roi.endpoint
}

output "database_secret_arn" {
  value = aws_secretsmanager_secret.database.arn
}

output "signing_key_arn" {
  value = aws_kms_key.agent_roi.arn
}
