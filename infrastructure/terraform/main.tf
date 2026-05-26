# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX — Multi-Region Terraform Infrastructure
# infrastructure/terraform/main.tf
# Version: 162.0.0
#
# Deployment Regions:
#   PRIMARY:   us-east-1  (AWS)   — North America / Global
#   SECONDARY: eu-west-1  (AWS)   — Europe (GDPR compliance)
#   TERTIARY:  ap-south-1 (AWS)   — Asia Pacific
#
# Components per region:
#   - EKS cluster (Sentinel APEX API + workers)
#   - RDS Aurora PostgreSQL (tenants, billing)
#   - ElastiCache Redis cluster (rate limiting, sessions)
#   - CloudFront CDN (static assets, edge caching)
#   - WAF v2 (API protection, rate limiting, geo-blocking)
#   - ClickHouse on EC2 (telemetry lake — us-east-1 primary only)
#   - Route53 latency routing (global DNS)
# =============================================================================

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.28"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
  }
  backend "s3" {
    bucket         = "cyberdudebivash-terraform-state"
    key            = "sentinel-apex/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

# ── Variables ────────────────────────────────────────────────────────────────
variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "platform_version" {
  description = "Sentinel APEX version tag"
  type        = string
  default     = "162.0"
}

variable "primary_region"   { default = "us-east-1" }
variable "secondary_region" { default = "eu-west-1" }
variable "tertiary_region"  { default = "ap-south-1" }

variable "eks_node_instance_type"    { default = "c6i.xlarge" }  # 4 vCPU, 8GB
variable "eks_min_nodes"             { default = 3 }
variable "eks_max_nodes"             { default = 50 }
variable "clickhouse_instance_type"  { default = "r6i.2xlarge" } # 8 vCPU, 64GB RAM

# ── Provider Configuration ───────────────────────────────────────────────────
provider "aws" {
  alias  = "primary"
  region = var.primary_region
  default_tags {
    tags = {
      Platform    = "CYBERDUDEBIVASH-SENTINEL-APEX"
      Environment = var.environment
      Version     = var.platform_version
      ManagedBy   = "Terraform"
    }
  }
}

provider "aws" {
  alias  = "eu"
  region = var.secondary_region
  default_tags {
    tags = {
      Platform    = "CYBERDUDEBIVASH-SENTINEL-APEX"
      Environment = var.environment
      Region      = "EU"
      GDPRScope   = "true"
    }
  }
}

provider "aws" {
  alias  = "apac"
  region = var.tertiary_region
  default_tags {
    tags = {
      Platform    = "CYBERDUDEBIVASH-SENTINEL-APEX"
      Environment = var.environment
      Region      = "APAC"
    }
  }
}

# ── VPCs ────────────────────────────────────────────────────────────────────

module "vpc_primary" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"
  providers = { aws = aws.primary }

  name = "sentinel-apex-primary"
  cidr = "10.0.0.0/16"

  azs              = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets   = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  database_subnets = ["10.0.201.0/24", "10.0.202.0/24", "10.0.203.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = false  # HA: one NAT per AZ
  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
}

module "vpc_eu" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"
  providers = { aws = aws.eu }

  name = "sentinel-apex-eu"
  cidr = "10.1.0.0/16"
  azs              = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  private_subnets  = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"]
  public_subnets   = ["10.1.101.0/24", "10.1.102.0/24", "10.1.103.0/24"]
  enable_nat_gateway   = true
  enable_dns_hostnames = true
}

module "vpc_apac" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"
  providers = { aws = aws.apac }

  name = "sentinel-apex-apac"
  cidr = "10.2.0.0/16"
  azs              = ["ap-south-1a", "ap-south-1b", "ap-south-1c"]
  private_subnets  = ["10.2.1.0/24", "10.2.2.0/24", "10.2.3.0/24"]
  public_subnets   = ["10.2.101.0/24", "10.2.102.0/24", "10.2.103.0/24"]
  enable_nat_gateway   = true
  enable_dns_hostnames = true
}

# ── EKS Clusters ─────────────────────────────────────────────────────────────

module "eks_primary" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"
  providers = { aws = aws.primary }

  cluster_name    = "sentinel-apex-primary"
  cluster_version = "1.29"
  vpc_id          = module.vpc_primary.vpc_id
  subnet_ids      = module.vpc_primary.private_subnets

  # Control plane access
  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]  # Lock down in prod

  # Encryption
  cluster_encryption_config = {
    resources = ["secrets"]
  }

  # Node groups
  eks_managed_node_groups = {
    api_workers = {
      name           = "api-workers"
      instance_types = [var.eks_node_instance_type]
      min_size       = var.eks_min_nodes
      max_size       = var.eks_max_nodes
      desired_size   = 5

      labels = { role = "api-worker" }
      taints = []

      # Spot instances for cost optimization (non-critical workers)
      capacity_type = "ON_DEMAND"

      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 50
            volume_type           = "gp3"
            iops                  = 3000
            throughput            = 125
            encrypted             = true
            delete_on_termination = true
          }
        }
      }
    }

    intel_workers = {
      name           = "intel-workers"
      instance_types = ["c6i.2xlarge"]  # CPU-optimized for ML scoring
      min_size       = 1
      max_size       = 20
      desired_size   = 2
      labels         = { role = "intel-worker" }
      capacity_type  = "SPOT"           # Cost-optimized for batch work
    }
  }

  # Add-ons
  cluster_addons = {
    coredns = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni = { most_recent = true }
    aws-ebs-csi-driver = { most_recent = true }
  }
}

# ── Aurora PostgreSQL (Multi-region) ─────────────────────────────────────────

module "aurora_primary" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 9.3"
  providers = { aws = aws.primary }

  name   = "sentinel-apex-db"
  engine = "aurora-postgresql"
  engine_version = "15.4"

  vpc_id  = module.vpc_primary.vpc_id
  subnets = module.vpc_primary.database_subnets

  instance_class = "db.r6g.xlarge"
  instances = {
    primary   = { instance_class = "db.r6g.xlarge" }
    replica-1 = { instance_class = "db.r6g.large" }
    replica-2 = { instance_class = "db.r6g.large" }
  }

  storage_encrypted = true
  monitoring_interval = 60

  # Global cluster for cross-region replication
  global_cluster_identifier = "sentinel-apex-global"

  # Backup
  backup_retention_period = 30
  preferred_backup_window = "02:00-04:00"

  # Performance Insights
  performance_insights_enabled          = true
  performance_insights_retention_period = 7

  serverlessv2_scaling_configuration = {
    min_capacity = 0.5
    max_capacity = 8
  }
}

# ── ElastiCache Redis Cluster ─────────────────────────────────────────────────

resource "aws_elasticache_replication_group" "sentinel_redis" {
  provider                  = aws.primary
  replication_group_id      = "sentinel-apex-redis"
  description               = "Sentinel APEX Redis Cluster - Rate limiting, sessions, queues"
  engine                    = "redis"
  engine_version            = "7.2"
  node_type                 = "cache.r7g.large"
  num_node_groups           = 3        # 3 shards
  replicas_per_node_group   = 2        # 2 replicas per shard = 6 total nodes
  automatic_failover_enabled = true
  multi_az_enabled          = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                = var.redis_auth_token

  subnet_group_name = aws_elasticache_subnet_group.sentinel.name
  security_group_ids = [aws_security_group.redis.id]

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }
}

# ── CloudFront Distribution ──────────────────────────────────────────────────

resource "aws_cloudfront_distribution" "sentinel_cdn" {
  provider    = aws.primary
  enabled     = true
  comment     = "Sentinel APEX CDN - Global Threat Intel Delivery"
  price_class = "PriceClass_All"  # All edge locations globally

  aliases = [
    "intel.cyberdudebivash.com",
    "api.cyberdudebivash.com",
    "cdn.intel.cyberdudebivash.com",
  ]

  # API Origin
  origin {
    domain_name = aws_lb.sentinel_api.dns_name
    origin_id   = "sentinel-api"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
    custom_header {
      name  = "X-Origin-Verify"
      value = var.cloudfront_origin_secret
    }
  }

  # Static Assets Origin
  origin {
    domain_name = aws_s3_bucket.sentinel_static.bucket_regional_domain_name
    origin_id   = "sentinel-static"
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.sentinel.cloudfront_access_identity_path
    }
  }

  # Default: Static assets
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "sentinel-static"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
  }

  # API routes — no caching for dynamic endpoints
  ordered_cache_behavior {
    path_pattern           = "/api/*"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "sentinel-api"
    viewer_protocol_policy = "https-only"
    compress               = true

    forwarded_values {
      query_string = true
      headers      = ["Authorization", "X-APEX-API-Key", "X-Tenant-ID"]
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 60     # 60s max for feed endpoints
  }

  web_acl_id = aws_wafv2_web_acl.sentinel.arn

  restrictions {
    geo_restriction {
      restriction_type = "none"  # Global access
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.sentinel.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# ── Route53 Latency Routing ──────────────────────────────────────────────────

resource "aws_route53_record" "sentinel_api_primary" {
  provider = aws.primary
  zone_id  = var.route53_zone_id
  name     = "intel.cyberdudebivash.com"
  type     = "A"

  set_identifier = "primary-us-east-1"
  latency_routing_policy {
    region = "us-east-1"
  }

  alias {
    name                   = aws_cloudfront_distribution.sentinel_cdn.domain_name
    zone_id                = aws_cloudfront_distribution.sentinel_cdn.hosted_zone_id
    evaluate_target_health = true
  }
}

# ── WAF v2 ───────────────────────────────────────────────────────────────────

resource "aws_wafv2_web_acl" "sentinel" {
  provider = aws.primary
  name     = "sentinel-apex-waf"
  scope    = "CLOUDFRONT"

  default_action { allow {} }

  # Rate limiting rule: 2000 req/5min per IP for free tier
  rule {
    name     = "RateLimitFree"
    priority = 10
    action { block {} }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string = "X-APEX-Tier: free"
            field_to_match { single_header { name = "x-apex-tier" } }
            text_transformations { priority = 0; type = "LOWERCASE" }
            positional_constraint = "EXACTLY"
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SentinelRateLimitFree"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules: Core Rule Set
  rule {
    name     = "AWSManagedRulesCRS"
    priority = 20
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SentinelCRS"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules: Known Bad Inputs
  rule {
    name     = "AWSManagedRulesBadInputs"
    priority = 30
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SentinelBadInputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "SentinelWAF"
    sampled_requests_enabled   = true
  }
}

# ── Outputs ──────────────────────────────────────────────────────────────────

output "eks_cluster_endpoint_primary" {
  value       = module.eks_primary.cluster_endpoint
  description = "Primary EKS cluster API endpoint"
}

output "cloudfront_domain" {
  value       = aws_cloudfront_distribution.sentinel_cdn.domain_name
  description = "CloudFront distribution domain"
}

output "redis_primary_endpoint" {
  value       = aws_elasticache_replication_group.sentinel_redis.primary_endpoint_address
  description = "Redis primary endpoint"
  sensitive   = true
}

output "aurora_writer_endpoint" {
  value       = module.aurora_primary.cluster_endpoint
  description = "Aurora PostgreSQL writer endpoint"
  sensitive   = true
}
