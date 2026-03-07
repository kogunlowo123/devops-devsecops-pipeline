output "waf_acl_arn" { value = aws_wafv2_web_acl.main.arn }
output "kms_key_arn" { value = aws_kms_key.data_encryption.arn }
output "kms_key_id" { value = aws_kms_key.data_encryption.key_id }
output "cloudtrail_arn" { value = aws_cloudtrail.main.arn }
output "guardduty_id" { value = aws_guardduty_detector.main.id }
