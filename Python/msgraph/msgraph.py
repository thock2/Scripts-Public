import requests
import json
import configparser

def get_graphtoken():
    # Import secret,ids from credentials.ini
    cred_object = configparser.ConfigParser()
    cred_object.read("credentials.ini")
    credentials = cred_object["entra-app"]

    # Create request body
    request_body = {
        "Grant_Type": "client_credentials",
        "Scope": "https://graph.microsoft.com/.default",
        "Client_Id": credentials["client_id"],
        "Client_Secret": credentials["client_secret"],
    }

    uri = f"https://login.microsoftonline.com/{credentials["tenant_id"]}/oauth2/v2.0/token"

    # Issue & parse request
    tokenResponse = requests.post(uri, data=request_body)

    # Create request headers
    request_headers = {
        "Authorization": f"Bearer {tokenResponse.json()['access_token']}",
        "Content-Type": "application/json",
    }

    return request_headers


def disable_azureaccount(userprincipalname):
    # Get auth token/headers
    token = get_graphtoken(client_secret, tenant_id, client_id)
    endpoints = [
        f"https://graph.microsoft.com/beta/users/{userprincipalname}/invalidateAllRefreshTokens",
        f"https://graph.microsoft.com/beta/users/{userprincipalname}/revokeSignInSessions",
    ]
    # Issue requests to invalidate tokens and revoke sign in sessions
    for uri in endpoints:
        request = requests.post(uri, headers=token)

    # Disable user, hide from address list
    disable_uri = f"https://graph.microsoft.com/beta/users/{userprincipalname}"
    disable_body = {"accountEnabled": "false", "showInAddressList": "false"}

    disable_request = requests.patch(
        disable_uri, headers=token, data=json.dumps(disable_body)
    )


def assign_license(license_type, *userprincipalname):
    # https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
    license_info = {
        "power_automate_free": "f30db892-07e9-47e9-837c-80727f46fd3d",
        "office_365_e3": "6fd2c87f-b296-42f0-b197-1e91e994b900",
        "office_365_e5": "c7df2760-2c81-4ef7-b578-5b5392b571df",
        "microsoft_365_business_basic": "3b555118-da6a-4418-894f-7df1e2096870",
    }

    if license_type not in license_info:
        print(f"Please enter a valid license type:\n {license_info}")
        exit

    else:
        # get token
        token = get_graphtoken(client_secret, tenant_id, client_id)
        # iterate through users and assign license
        for user in userprincipalname:
            # License assignment endpoint
            uri = f"https://graph.microsoft.com/beta/users/{user}/assignLicense"
            # Body of licenses
            license_body = {
                "addLicenses": [{"skuId": license_info[license_type]}],
                "removeLicenses": [],
            }
            license_request = requests.post(
                uri, headers=token, data=json.dumps(license_body)
            )


def remove_licenses(*userprincipalname):
    # Get auth token
    token = get_graphtoken(client_secret, tenant_id, client_id)
    # iterate through users
    for user in userprincipalname:
        # Get all licenses assigned to user
        assigned_uri = (
            f"https://graph.microsoft.com/beta/users/{user}?$select=assignedLicenses"
        )
        assigned = requests.get(assigned_uri, headers=token)
        # for each license, issue remove request
        for license in assigned.json()["assignedLicenses"]:
            # print(license['skuId'])
            license_body = {"addLicenses": [], "removeLicenses": [license["skuId"]]}
            removal_uri = f"https://graph.microsoft.com/beta/users/{user}/assignLicense"
            removal = requests.post(
                removal_uri, headers=token, data=json.dumps(license_body)
            )


def send_email(from_address, to_address, subject, body, attachment=None):
    # Get token
    token = get_graphtoken(client_secret, tenant_id, client_id)
    # define sender uri
    sender_uri = f"https://graph.microsoft.com/v1.0/users/{from_address}/sendMail"
    # create message body
    message_body = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
            "toRecipients": [{"emailAddress": {"address": to_address}}],
        }
    }
    # send e-mail
    message_send = requests.post(
        sender_uri, headers=token, data=json.dumps(message_body)
    )
    print(message_send.text)


def send_email_2(from_address, to_address, subject, body, attachment=None):
    # Get token
    token = get_graphtoken(client_secret, tenant_id, client_id)
    # define sender uri
    sender_uri = f"https://graph.microsoft.com/v1.0/users/{from_address}/sendMail"
    # create message body
    message_body = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
            "toRecipients": [{"emailAddress": {"address": to_address}}],
            "attachments": [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "",
                    "contentType": "",
                    "contentBytes": "",
                }
            ],
            "saveToSentItems": "true",
        }
    }
    # send e-mail
    message_send = requests.post(
        sender_uri, headers=token, data=json.dumps(message_body)
    )
    print(message_send.text)
