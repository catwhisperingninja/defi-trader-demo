#!/usr/bin/env python3
"""
Initialize Azure Key Vault with secrets from environment variables using Azure CLI.
Run this script once to upload secrets from .env to Azure Key Vault.
"""
import os
import sys
import logging
import subprocess
from dotenv import load_dotenv
from typing import List, Tuple, Any

# Import the local azure_key_vault_cli module using consistent approach
import importlib.util

azure_cli_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'azure_key_vault_cli.py')
spec = importlib.util.spec_from_file_location("azure_key_vault_cli", azure_cli_path)
if spec is None or spec.loader is None:
    raise ImportError("Could not load azure_key_vault_cli module")
key_vault = importlib.util.module_from_spec(spec)
sys.modules["azure_key_vault_cli_init"] = key_vault
spec.loader.exec_module(key_vault)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_required_env_vars() -> bool:
    """Check that all required environment variables are set."""
    # At least one of these must be set
    if not os.getenv('AZURE_KEYVAULT_NAME') and not os.getenv('AZURE_KEYVAULT_URI'):
        logger.error("Missing required environment variables:")
        logger.error("  - AZURE_KEYVAULT_NAME - The name of your Azure Key Vault")
        logger.error("  - AZURE_KEYVAULT_URI - The URI of your Azure Key Vault")
        logger.error("At least one of these must be set.")
        return False

    # Check for service principal credentials
    if not (os.getenv('AZURE_CLIENT_ID') or os.getenv('AZURE_APP_ID')) or not os.getenv('AZURE_CLIENT_SECRET'):
        logger.error("Missing Azure authentication credentials:")
        logger.error("  - AZURE_CLIENT_ID or AZURE_APP_ID - The client ID for Azure authentication")
        logger.error("  - AZURE_CLIENT_SECRET - The client secret for Azure authentication")
        return False

    return True

def check_azure_cli() -> bool:
    """Check if Azure CLI is available."""
    try:
        result = subprocess.run(
            ["az", "account", "show", "--query", "name", "-o", "tsv"],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            logger.error("Azure CLI is not available or not logged in.")
            logger.error(f"Error: {result.stderr}")
            return False

        logger.info("Azure CLI is available and authenticated.")
        return True
    except Exception as e:
        logger.error(f"Failed to run Azure CLI: {e}")
        return False

def login_with_service_principal() -> bool:
    """Login to Azure CLI using service principal credentials if not already logged in."""
    client_id = os.getenv('AZURE_CLIENT_ID') or os.getenv('AZURE_APP_ID')
    client_secret = os.getenv('AZURE_CLIENT_SECRET')

    if not client_id or not client_secret:
        logger.error("Missing authentication credentials")
        return False

    try:
        # First check if already logged in
        account_check = subprocess.run(
            ["az", "account", "show", "--query", "name", "-o", "tsv"],
            capture_output=True,
            text=True,
            check=False
        )

        if account_check.returncode == 0:
            logger.info("Already authenticated")
            return True

        # If not logged in, attempt login with service principal
        logger.info("Authenticating")

        # Prepare login command - don't log any details
        login_cmd = [
            "az", "login", "--service-principal",
            "--username", client_id,
            "--password", client_secret
        ]

        result = subprocess.run(
            login_cmd,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            logger.error("Authentication failed")
            return False

        logger.info("Authentication successful")
        return True
    except Exception as e:
        # Don't log any exception details as they might contain credentials
        logger.error("Authentication error")
        return False

def main() -> None:
    """Initialize Key Vault with secrets from .env file."""
    # Load environment variables
    load_dotenv()

    # Check for required environment variables
    logger.info("Checking environment variables")
    if not check_required_env_vars():
        sys.exit(1)

    # Handle service principal login
    logger.info("Setting up Azure authentication")
    if not login_with_service_principal():
        logger.error("Azure authentication setup failed")
        sys.exit(1)

    # Check Azure CLI availability
    logger.info("Checking Azure CLI")
    if not check_azure_cli():
        logger.error("Azure CLI issues detected")
        sys.exit(1)

    # Log the values we're using (without exposing sensitive data)
    azure_keyvault_uri = os.getenv('AZURE_KEYVAULT_URI')
    azure_keyvault_name = os.getenv('AZURE_KEYVAULT_NAME')

    if azure_keyvault_name:
        logger.info("Using configured Key Vault")
    elif azure_keyvault_uri:
        logger.info("Using configured Key Vault URI")
        vault_name = azure_keyvault_uri.split('.')[0].split('//')[1] if azure_keyvault_uri else None
        if vault_name:
            logger.info("Extracted Key Vault name")

    try:
        logger.info("Initializing configuration")

        # Step 1: Upload secrets from .env to Key Vault
        results = key_vault.init_from_env()
        success_count = sum(1 for _, success in results if success)
        total_count = len(results)

        logger.info(f"Configuration: {success_count}/{total_count} items processed")

        if success_count != total_count:
            logger.error("Configuration incomplete")
            sys.exit(1)

        # Step 2: Test retrieval of secrets from Key Vault
        logger.info("Testing configuration")
        test_results = key_vault.test_secrets()

        test_success_count = sum(1 for _, success in test_results if success)
        test_total_count = len(test_results)

        logger.info(f"Test: {test_success_count}/{test_total_count} items verified")

        if test_success_count != test_total_count:
            logger.error("Configuration verification failed")
            sys.exit(1)

        logger.info("=== INITIALIZATION SUCCESSFUL ===")
        logger.info("Key Vault configuration complete")

    except Exception as e:
        logger.error("Initialization failed")
        sys.exit(1)

if __name__ == "__main__":
    main()