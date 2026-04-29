terraform {
  required_providers {
    fw-analyzer = {
      source = "local/fw-analyzer"
    }
  }
}

provider "fw-analyzer" {}

# 🔍 Run analysis
data "fw-analyzer_analysis" "check" {
  policy_json = file("${path.module}/policy.json")
}

# 📤 Output results
output "findings" {
  value = data.fw-analyzer_analysis.check.findings
}
