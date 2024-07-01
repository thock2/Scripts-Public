import msgraph
import argparse

# Create / parse argument
argument = argparse.ArgumentParser()
argument.add_argument("email_address", help="Provide e-mail address of user")
arguments = argument.parse_args()

# Disable account
msgraph.disable_azureaccount("testuser@example.com")
# Remove License
msgraph.remove_licenses("testuser@example.com")
# E-mail IT confirming completion
msgraph.send_email(
    "no-reply@example.xom)",
    "it@example.com",
    f"User Deactivation - {argument.email_address}",
    f"{argument.email_address} has been deactivated",
)
