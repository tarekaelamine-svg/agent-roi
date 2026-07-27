terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
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

resource "google_kms_key_ring" "agent_roi" {
  name     = var.name
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "signing" {
  name     = "policy-signing"
  key_ring = google_kms_key_ring.agent_roi.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "RSA_SIGN_PSS_3072_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_sql_database_instance" "agent_roi" {
  name                = var.name
  project             = var.project_id
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  settings {
    tier              = "db-custom-2-7680"
    availability_type = "REGIONAL"
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = var.network
      enable_private_path_for_google_cloud_services = true
    }
  }
}

resource "google_sql_database" "agent_roi" {
  name     = var.database_name
  instance = google_sql_database_instance.agent_roi.name
  project  = var.project_id
}

resource "google_sql_user" "agent_roi" {
  name     = var.database_username
  instance = google_sql_database_instance.agent_roi.name
  password = random_password.database.result
  project  = var.project_id
}

resource "google_secret_manager_secret" "database" {
  secret_id = "${var.name}-postgres"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "database" {
  secret = google_secret_manager_secret.database.id
  secret_data = jsonencode({
    user            = google_sql_user.agent_roi.name
    password        = random_password.database.result
    database        = google_sql_database.agent_roi.name
    connection_name = google_sql_database_instance.agent_roi.connection_name
  })
}
