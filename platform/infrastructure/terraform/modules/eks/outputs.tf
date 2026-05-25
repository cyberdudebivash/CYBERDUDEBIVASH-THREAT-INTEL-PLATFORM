output "cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = ""
}

output "cluster_certificate_authority_data" {
  description = "EKS cluster CA certificate (base64)"
  value       = ""
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = ""
}

output "cluster_security_group_id" {
  description = "EKS cluster security group ID"
  value       = ""
}

output "node_group_role_arn" {
  description = "IAM role ARN for EKS node group"
  value       = ""
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN for IRSA"
  value       = ""
}
