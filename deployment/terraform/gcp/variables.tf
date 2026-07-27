variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "name" {
  type    = string
  default = "agent-roi"
}

variable "network" {
  type = string
}

variable "database_name" {
  type    = string
  default = "agentroi"
}

variable "database_username" {
  type    = string
  default = "agentroi"
}
