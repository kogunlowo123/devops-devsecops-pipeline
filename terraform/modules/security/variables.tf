variable "environment" { type = string }
variable "aws_region" { type = string, default = "us-east-1" }
variable "account_id" { type = string }
variable "data_classification" { type = string, default = "Sensitive" }
variable "common_tags" { type = map(string), default = {} }
