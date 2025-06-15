from google.cloud import secretmanager

def access_secret_version(
        project_id: str, secret_id: str, version_id: str = "latest"
):
    """
    Access secret manager for passwords
    """
    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    # Access the secret version
    response = client.access_secret_version(request={"name": name})

    # Return the response
    return response.payload.data.decode("UTF-8")