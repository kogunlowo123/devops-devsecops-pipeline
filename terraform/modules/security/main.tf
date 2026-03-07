# Security Infrastructure Module
# Architect: Kehinde (Kenny) Samson Ogunlowo
# Implements NIST 800-53, HIPAA, and CMMC Level 2 controls

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }
  tags = merge(var.common_tags, { Name = "${var.environment}-guardduty", Compliance = "NIST-800-53-SI-3" })
}

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "nist" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
}

resource "aws_kms_key" "data_encryption" {
  description             = "HIPAA PHI / Sensitive Data Encryption Key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = merge(var.common_tags, { Name = "${var.environment}-phi-kms-key", Compliance = "HIPAA-164.312-a-2-iv" })
}

resource "aws_kms_alias" "data_encryption" {
  name          = "alias/${var.environment}-phi-encryption"
  target_key_id = aws_kms_key.data_encryption.key_id
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.data_encryption.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_role.arn
  tags = merge(var.common_tags, { Compliance = "HIPAA-164.312-b,CMMC-AU-3" })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.environment}"
  retention_in_days = 2557  # 7 years - HIPAA requirement
  kms_key_id        = aws_kms_key.data_encryption.arn
  tags              = var.common_tags
}

resource "aws_wafv2_web_acl" "main" {
  name        = "${var.environment}-enterprise-waf"
  description = "Enterprise WAF - OWASP Top 10 + SQL Injection + Rate Limiting"
  scope       = "REGIONAL"

  default_action { allow {} }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitRule"
    priority = 2
    action { block {} }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "EnterpriseWAFMetric"
    sampled_requests_enabled   = true
  }

  tags = merge(var.common_tags, { Compliance = "OWASP-Top-10" })
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.environment}-cloudtrail-logs-${var.account_id}"
  force_destroy = false
  tags          = merge(var.common_tags, { DataClass = "Audit-Logs", Compliance = "HIPAA-Required" })
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data_encryption.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "cloudtrail_role" {
  name = "${var.environment}-cloudtrail-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role" "config_role" {
  name = "${var.environment}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "config.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}
