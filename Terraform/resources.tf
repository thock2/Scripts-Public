#https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group#location
## Resource Group
resource "azurerm_resource_group" "powerapp-test-group" {
  name     = "powerapp-test-group"
  location = "East US"
}

#https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/automation_account
## Automation Account

resource "azurerm_automation_account" "powerapp-test-account" {
  name                = "powerapp-test-account"
  location            = azurerm_resource_group.powerapp-test-group.location
  resource_group_name = azurerm_resource_group.powerapp-test-group.name
  sku_name            = "Basic"
}

## Script to place in general runbook
data "local_file" "create-file" {
  filename = "${path.module}/Scripts/create-file.ps1"
}

## Script to place in dc runbook
data "local_file" "disable-user" {
  filename = "${path.module}/Scripts/disable_user.ps1"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/automation_hybrid_runbook_worker_group
## Worker Group
resource "azurerm_automation_hybrid_runbook_worker_group" "powerapp-test-worker-group" {
  name                    = "powerapp-test-worker-group"
  resource_group_name     = azurerm_resource_group.powerapp-test-group.name
  automation_account_name = azurerm_automation_account.powerapp-test-account.name
}

resource "azurerm_automation_hybrid_runbook_worker_group" "powerapp-test-dc-worker-group" {
  name                    = "powerapp-test-dc-worker-group"
  resource_group_name     = azurerm_resource_group.powerapp-test-group.name
  automation_account_name = azurerm_automation_account.powerapp-test-account.name
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/automation_runbook
## Runbook Creation (General)
resource "azurerm_automation_runbook" "powerapp-test-runbook" {
  name                    = "Create-File"
  location                = azurerm_resource_group.powerapp-test-group.location
  resource_group_name     = azurerm_resource_group.powerapp-test-group.name
  automation_account_name = azurerm_automation_account.powerapp-test-account.name
  log_verbose             = "true"
  log_progress            = "true"
  description             = "Creates a file"
  runbook_type            = "PowerShell"

  content = data.local_file.create-file.content
}

## Runbook Creation (DC)
resource "azurerm_automation_runbook" "disable-user-runbook" {
  name                    = "Disable-User"
  location                = azurerm_resource_group.powerapp-test-group.location
  resource_group_name     = azurerm_resource_group.powerapp-test-group.name
  automation_account_name = azurerm_automation_account.powerapp-test-account.name
  log_verbose             = "true"
  log_progress            = "true"
  description             = "Disables an Active Directory User"
  runbook_type            = "PowerShell"

  content = data.local_file.disable-user.content
}

