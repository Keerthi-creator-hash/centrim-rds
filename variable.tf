variable "region" {
  type = string
  default = "eu-north-1"
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}
