terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
  }
}

resource "random_password" "database" {
  length           = 32
  special          = true
  override_special = "!#$%&*+-=?^_"
}

resource "aws_kms_key" "agent_roi" {
  description             = "Agent-ROI signing and storage key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_db_subnet_group" "agent_roi" {
  name       = var.name
  subnet_ids = var.subnet_ids
}

resource "aws_security_group" "database" {
  name        = "${var.name}-postgres"
  description = "PostgreSQL access for Agent-ROI"
  vpc_id      = var.vpc_id
}

resource "aws_security_group_rule" "database_ingress" {
  for_each = toset(var.allowed_security_group_ids)

  type                     = "ingress"
  security_group_id        = aws_security_group.database.id
  source_security_group_id = each.value
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
}

resource "aws_rds_cluster" "agent_roi" {
  cluster_identifier              = var.name
  engine                          = "aurora-postgresql"
  engine_mode                     = "provisioned"
  database_name                   = var.database_name
  master_username                 = var.database_username
  master_password                 = random_password.database.result
  db_subnet_group_name            = aws_db_subnet_group.agent_roi.name
  vpc_security_group_ids          = [aws_security_group.database.id]
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.agent_roi.arn
  backup_retention_period         = 14
  deletion_protection             = var.deletion_protection
  enabled_cloudwatch_logs_exports = ["postgresql"]
  copy_tags_to_snapshot            = true
  skip_final_snapshot              = false
  final_snapshot_identifier        = "${var.name}-final"
}

resource "aws_rds_cluster_instance" "agent_roi" {
  count = 2

  identifier         = "${var.name}-${count.index + 1}"
  cluster_identifier = aws_rds_cluster.agent_roi.id
  instance_class     = var.instance_class
  engine             = aws_rds_cluster.agent_roi.engine
}

resource "aws_secretsmanager_secret" "database" {
  name       = "${var.name}/postgres"
  kms_key_id = aws_kms_key.agent_roi.arn
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username = var.database_username
    password = random_password.database.result
    host     = aws_rds_cluster.agent_roi.endpoint
    port     = 5432
    dbname   = var.database_name
  })
}
