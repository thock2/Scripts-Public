import msgraph
import argparse

# Create / parse argument
argument = argparse.ArgumentParser()
argument.add_argument("email_address", help="Provide e-mail address of user", nargs="*")
arguments = argument.parse_args()

for user in arguments.email_address:
    # Disable account
    print(msgraph.disable_azureaccount(user))
    # Remove License
    msgraph.remove_licenses(user)
    # E-mail IT confirming completion
    msgraph.send_email(
        "it@example.com",
        "testuser@example.com",
        f"User Deactivation - {user}",
        f"{user} has been deactivated",
    )
