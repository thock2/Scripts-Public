variable "client_id" {
  type        = string
  description = "Client ID"
}

variable "client_secret" {
  description = "Enter the client secret here."
  sensitive   = true
}

variable "tenant_id" {
  type        = string
  description = "Tenant ID"
}

variable "subscription_id" {
  type        = string
  description = "Subscription ID"
}
