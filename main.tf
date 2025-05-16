# Data source to get available availability zones
data "aws_availability_zones" "available" {}

#  Create VPC
resource "aws_vpc" "api_stage_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "api_stage-vpc"
  }
}

# THEN: Create Subnets inside VPC
resource "aws_subnet" "public_subnet" {
  count = 3

  vpc_id                  = aws_vpc.api_stage_vpc.id
  cidr_block              = cidrsubnet(aws_vpc.api_stage_vpc.cidr_block, 8, count.index)
  availability_zone       = element(data.aws_availability_zones.available.names, count.index)
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-${count.index + 1}"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "api_stage_igw" {
  vpc_id = aws_vpc.api_stage_vpc.id
  tags = {
    Name = "api_stage-igw"
  }
}
# Security Group
resource "aws_security_group" "api_stage_sg" {
  name        = "api-stage-sg"
  description = "Allow HTTP and SSH"

  vpc_id = aws_vpc.api_stage_vpc.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "api-stage-sg"
  }
}
# DB Subnet Group
resource "aws_db_subnet_group" "default" {
  name       = "default-subnet-group"
  subnet_ids = aws_subnet.public_subnet[*].id

  tags = {
    Name = "default-subnet-group"
  }
}

#  RDS Instance
resource "aws_db_instance" "rds_instance" {
  identifier             = "centrimstaging1"
  allocated_storage      = 20
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  username               = "admin"
  password               = var.db_password
  db_name                = "centrimdb"
  vpc_security_group_ids = [aws_security_group.api_stage_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.default.name
  availability_zone      = "eu-north-1c" 
  skip_final_snapshot    = true
  publicly_accessible    = false

  tags = {
    Name = "centrimstaging1"
  }
}
resource "aws_elasticache_subnet_group" "redis_subnet_group" {
  name       = "redis-subnet-group"
  subnet_ids = aws_subnet.public_subnet[*].id 
  }

 resource "aws_elasticache_cluster" "redis" {
  cluster_id        = "centriem-redis"
  engine            = "redis"
  engine_version    = "5.0.6"  # Valid version from AWS CLI output
  node_type         = "cache.t3.micro"
  num_cache_nodes   = 1
  parameter_group_name = "default.redis5.0"
  subnet_group_name = aws_elasticache_subnet_group.redis_subnet_group.name  
  }

# Create S3 Bucket for App
resource "aws_s3_bucket" "centrimstaging1" {
  bucket = "centrimstaging1-bucket"
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "centrimstaging1_versioning" {
  bucket = aws_s3_bucket.centrimstaging1.id

  versioning_configuration {
    status = "Disabled"
  }
}

# S3 Bucket for Logs
resource "aws_s3_bucket" "log" {
  bucket = "my-uniquecentri-s3-logs-bucket1"
}

# Ensure S3 bucket is created before applying policies
resource "aws_s3_bucket_logging" "logging" {
  bucket        = aws_s3_bucket.centrimstaging1.id
  target_bucket = aws_s3_bucket.log.id
  target_prefix = "logs/"
}

# S3 Bucket Policy for WAF Logging (Ensured proper dependency)
resource "aws_s3_bucket_policy" "waf_logging_policy" {
  bucket = aws_s3_bucket.log.id
  depends_on = [aws_s3_bucket.log]  # Ensures bucket creation happens first

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowWAFLogging",
        Effect    = "Allow",
        Principal = {
          Service = "waf.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "${aws_s3_bucket.log.arn}/*",
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = "861276114155"
          }
        }
      }
    ]
  })
}

# CloudTrail Bucket Policy (Ensuring logging permissions)
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.log.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowCloudTrailLogging",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "${aws_s3_bucket.log.arn}/*",
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = "861276114155"
          }
        }
      }
    ]
  })
}
# CloudFront Distribution for S3 Bucket
resource "aws_cloudfront_distribution" "centrim_cloudfront" {
  origin {
    domain_name = aws_s3_bucket.centrimstaging1.bucket_regional_domain_name
    origin_id   = "S3-centrimstaging1-bucket"
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-centrimstaging1-bucket"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Name = "CentriCloudFront"
  }
}


# CloudWatch Log Group for Staging
resource "aws_cloudwatch_log_group" "staging_logs" {
  name              = "/aws/staging-group"
  retention_in_days = 14
}

# CloudTrail Configuration (Ensure correct bucket reference)
resource "aws_cloudtrail" "trail" {
  name                          = "centrimlife-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.log.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
resource "aws_s3_bucket_policy" "cloudtrail_policyv2" {
  bucket = aws_s3_bucket.log.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:GetBucketAcl",
        Resource = "${aws_s3_bucket.log.arn}",
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:eu-north-1:861276114155:trail/centrimlife-cloudtrail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "${aws_s3_bucket.log.arn}/AWSLogs/861276114155/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control",
            "aws:SourceArn" = "arn:aws:cloudtrail:eu-north-1:861276114155:trail/centrimlife-cloudtrail"
          }
        }
      }
    ]
  })
}
resource "aws_wafv2_web_acl" "centrim_waf_acl" {
  name        = "centrim-aus-stage"
  description = "WAF ACL for application security"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "block-bad-traffic"
    priority = 1

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        rule_action_override {
          action_to_use {
            count {}
          }
          name = "SizeRestrictions_QUERYSTRING"
        }

        rule_action_override {
          action_to_use {
            count {}
          }
          name = "NoUserAgent_HEADER"
        }

        scope_down_statement {
          geo_match_statement {
            country_codes = ["IN", "US"]
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "centrim-block-rule-metric"
      sampled_requests_enabled   = false
    }
  }

  tags = {
    Project = "Centrim"
    Environment = "Stage"
  }

  token_domains = ["centrim.com", "centrim-stage.com"]

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "centrim-acl-metric"
    sampled_requests_enabled   = false
  }
}
