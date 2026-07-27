variable "name" {
  type    = string
  default = "agent-roi"
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "allowed_security_group_ids" {
  type    = list(string)
  default = []
}

variable "database_name" {
  type    = string
  default = "agentroi"
}

variable "database_username" {
  type    = string
  default = "agentroi"
}

variable "instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "deletion_protection" {
  type    = bool
  default = true
}
