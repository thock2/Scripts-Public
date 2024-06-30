import msgraph

# Disable account
msgraph.disable_azureaccount("testuser@example.com")
# Remove License
msgraph.remove_licenses("testuser@example.com")
# E-mail IT confirming completion
