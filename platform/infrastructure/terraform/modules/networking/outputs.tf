output "vpc_id" {
  description = "VPC ID"
  value       = ""
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = tolist([])
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = tolist([])
}

output "database_subnet_group_name" {
  description = "RDS subnet group name"
  value       = ""
}

output "rds_security_group_id" {
  description = "RDS security group ID"
  value       = ""
}

output "redis_subnet_group_name" {
  description = "ElastiCache subnet group name"
  value       = ""
}

output "redis_security_group_id" {
  description = "Redis security group ID"
  value       = ""
}

output "kafka_security_group_id" {
  description = "MSK Kafka security group ID"
  value       = ""
}

output "eks_security_group_id" {
  description = "EKS cluster security group ID"
  value       = ""
}
