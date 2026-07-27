variable "name" {
  type    = string
  default = "agent-roi"
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "administrator_login" {
  type    = string
  default = "agentroi"
}

variable "database_name" {
  type    = string
  default = "agentroi"
}
