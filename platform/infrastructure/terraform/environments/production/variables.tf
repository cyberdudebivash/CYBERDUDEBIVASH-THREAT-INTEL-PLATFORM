variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "domain" {
  description = "Primary domain for SENTINEL APEX"
  type        = string
  default     = "intel.cyberdudebivash.com"
}

variable "admin_cidrs" {
  description = "CIDRs allowed to access EKS public endpoint"
  type        = list(string)
  default     = []
}

variable "alert_email" {
  description = "Email for CloudWatch alarms"
  type        = string
  default     = "bivash@cyberdudebivash.com"
}
