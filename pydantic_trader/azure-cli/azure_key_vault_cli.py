"""
Azure Key Vault integration using Azure CLI for secure credential management.
This implementation uses Azure CLI commands instead of the Azure SDK.
"""
import os
import json
import logging
import time
import subprocess
from datetime import datetime
from typing import Dict, Optional, Any, List, Tuple, Union
from functools import lru_cache

logger = logging.getLogger(__name__)

class KeyVaultClient:
    """Client for retrieving secrets from Azure Key Vault using Azure CLI with fallback to environment variables."""

    def __init__(self):
        """Prepare Key Vault client data."""
        # Cache for secrets to minimize CLI calls
        self._secret_cache: Dict[str, Dict[str, Any]] = {}

        # Read configuration from environment
        self.key_vault_uri = os.getenv('AZURE_KEYVAULT_URI')
        self.key_vault_name = os.getenv('AZURE_KEYVAULT_NAME')
        self.client_id = os.getenv('AZURE_CLIENT_ID')
        self.app_id = os.getenv('AZURE_APP_ID')
        self.client_secret = os.getenv('AZURE_CLIENT_SECRET')
        self.resource_group = os.getenv('AZURE_RESOURCE_GROUP')

        # If key_vault_name is not provided directly, try to extract from URI
        if not self.key_vault_name and self.key_vault_uri:
            self.key_vault_name = self._extract_vault_name(self.key_vault_uri)

        if self.client_id or self.app_id:
            if self.client_secret:
                logger.debug("Programmatic authentication configured")
            else:
                logger.debug("Programmatic authentication partially configured. Authentication may fail.")
        else:
            logger.debug("No programmatic auth found. Authentication may fail.")

        if self.resource_group:
            logger.debug("Using configured resource group")

    def _extract_vault_name(self, vault_uri: str) -> str:
        """Extract the vault name from the URI."""
        if not vault_uri:
            return ""
        # Extract vault name from URI like https://vault-name.vault.azure.net/
        try:
            return vault_uri.split('.')[0].split('//')[1]
        except (IndexError, AttributeError):
            logger.error("Failed to extract vault name from URI")
            return ""

    def _get_identity_args(self) -> List[str]:
        """Get command arguments for programmatic authentication."""
        # Programmatic authentication
        return ["--only-show-errors"]

    def _run_azure_cli(self, command: List[str]) -> Tuple[bool, str]:
        """
        Run an Azure CLI command.

        Args:
            command: List of command parts to execute

        Returns:
            Tuple of (success, output)
        """
        try:
            full_command = ["az"] + command

            # Check if this is a sensitive command that should not be logged at all
            if not self._should_log_command(full_command):
                # Run without logging
                result = subprocess.run(
                    full_command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30
                )
            else:
                # Only log non-sensitive commands
                logger.debug(f"Running Azure CLI command: {' '.join(full_command)}")
                result = subprocess.run(
                    full_command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30
                )

            if result.returncode == 0:
                # Only log success for non-sensitive operations, no details
                return True, result.stdout.strip()
            else:
                # For errors, don't include stderr details for sensitive operations
                if self._is_sensitive_operation(command):
                    # Just log generic error for sensitive operations
                    logger.error("Azure CLI operation failed")
                else:
                    logger.error(f"Azure CLI error: {result.stderr}")

                return False, result.stderr.strip()

        except subprocess.TimeoutExpired:
            logger.error("Azure CLI command timed out after 30 seconds")
            return False, "Command timeout"
        except Exception as e:
            # Don't log exception details which might contain sensitive info
            logger.error("Failed to run Azure CLI command")
            return False, str(e)

    def _should_log_command(self, cmd: List[str]) -> bool:
        """
        Determine if a command should be logged based on its sensitivity.

        Args:
            cmd: The command parts as a list

        Returns:
            True if command can be safely logged, False if it's sensitive
        """
        sensitive_operations = ["keyvault", "secret", "login", "password", "key", "token", "credential"]
        cmd_str = " ".join(cmd).lower()
        return not any(op in cmd_str for op in sensitive_operations)

    def _is_sensitive_operation(self, cmd: List[str]) -> bool:
        """
        Check if this is a sensitive operation that needs special handling.

        Args:
            cmd: The command parts as a list

        Returns:
            True if this is a sensitive operation, False otherwise
        """
        sensitive_operations = ["keyvault", "secret", "login", "password", "key", "token", "credential"]
        cmd_str = " ".join(cmd).lower()
        return any(op in cmd_str for op in sensitive_operations)

    def get_secret(self, secret_name: str, default_env_var: Optional[str] = None,
                   max_age_seconds: int = 300) -> Optional[str]:
        """
        Retrieve a secret from Azure Key Vault with caching and fallback to environment variables.

        Args:
            secret_name: Name of the secret in Key Vault
            default_env_var: Environment variable name to use as fallback
            max_age_seconds: Maximum age of cached secrets before refreshing

        Returns:
            Secret value or None if not found
        """
        # Check if secret is in cache and not expired
        if secret_name in self._secret_cache:
            cache_entry = self._secret_cache[secret_name]
            if time.time() - cache_entry['timestamp'] < max_age_seconds:
                return cache_entry['value']

        # 1. Try environment variable first to avoid unnecessary Azure CLI calls
        if default_env_var:
            env_value = os.getenv(default_env_var)
            if env_value is not None:
                # Cache and return
                self._secret_cache[secret_name] = {
                    'value': env_value,
                    'timestamp': time.time()
                }
                return env_value

        # 2. If env var not present and vault name is available, attempt to fetch from Key Vault
        if self.key_vault_name:
            cmd = [
                "keyvault", "secret", "show",
                "--vault-name", self.key_vault_name,
                "--name", secret_name,
                "--query", "value",
                "-o", "tsv"
            ]

            # Note: --resource-group is not supported for Key Vault secret operations

            # Add identity args
            identity_args = self._get_identity_args()
            cmd.extend(identity_args)

            success, output = self._run_azure_cli(cmd)

            if success:
                # Cache and return
                self._secret_cache[secret_name] = {
                    'value': output,
                    'timestamp': time.time()
                }
                return output
            else:
                logger.warning("Failed to retrieve secret from Key Vault")

        return None

    def set_secret(self, secret_name: str, secret_value: str) -> Tuple[bool, str]:
        """
        Save a secret to Azure Key Vault and return secret identifier.

        Args:
            secret_name: Name of the secret in Key Vault
            secret_value: Value of the secret

        Returns:
            Tuple of (success_status, secret_identifier_or_error)
        """
        if not self.key_vault_name:
            logger.error("Key Vault name not available")
            return False, "Key Vault name not available"

        cmd = [
            "keyvault", "secret", "set",
            "--vault-name", self.key_vault_name,
            "--name", secret_name,
            "--value", secret_value,
            "--query", "id",
            "-o", "tsv"
        ]

        # Add identity args
        identity_args = self._get_identity_args()
        cmd.extend(identity_args)

        success, output = self._run_azure_cli(cmd)

        if success:
            # Update cache
            self._secret_cache[secret_name] = {
                'value': secret_value,
                'timestamp': time.time()
            }
            return True, output.strip()  # Return secret identifier
        else:
            return False, output

    def get_secret_by_id(self, secret_id: str) -> Optional[str]:
        """
        Retrieve a secret from Azure Key Vault by secret identifier.

        Args:
            secret_id: Full secret identifier URL

        Returns:
            Secret value or None if not found
        """
        cmd = [
            "keyvault", "secret", "show",
            "--id", secret_id,
            "--query", "value",
            "-o", "tsv"
        ]

        # Add identity args
        identity_args = self._get_identity_args()
        cmd.extend(identity_args)

        success, output = self._run_azure_cli(cmd)

        if success:
            return output
        else:
            logger.warning("Failed to retrieve secret by ID")
            return None

    def delete_secret(self, secret_name: str) -> bool:
        """
        Delete a secret from Azure Key Vault (soft delete).

        Args:
            secret_name: Name of the secret to delete

        Returns:
            Success status (True/False)
        """
        if not self.key_vault_name:
            logger.error("Key Vault name not available")
            return False

        cmd = [
            "keyvault", "secret", "delete",
            "--vault-name", self.key_vault_name,
            "--name", secret_name
        ]

        # Add identity args
        identity_args = self._get_identity_args()
        cmd.extend(identity_args)

        success, output = self._run_azure_cli(cmd)

        if success:
            # Remove from cache if present
            if secret_name in self._secret_cache:
                del self._secret_cache[secret_name]
            return True
        else:
            return False

    def list_secrets(self) -> List[str]:
        """
        List all secrets in the Key Vault.

        Returns:
            List of secret names
        """
        if not self.key_vault_name:
            logger.error("Key Vault name not available, cannot list secrets")
            return []

        cmd = [
            "keyvault", "secret", "list",
            "--vault-name", self.key_vault_name,
            "--query", "[].name",
            "-o", "json"
        ]

        # Note: --resource-group is not supported for the 'list' command

        # Add identity args
        identity_args = self._get_identity_args()
        if identity_args:
            cmd.extend(identity_args)

        success, output = self._run_azure_cli(cmd)

        if success:
            try:
                return json.loads(output)
            except json.JSONDecodeError as e:
                logger.error("Failed to parse secret list")
                return []
        else:
            logger.error("Failed to list secrets in Key Vault")
            return []

    def clear_cache(self):
        """Clear the secret cache, forcing refresh on next retrieval."""
        self._secret_cache.clear()
        logger.debug("Secret cache cleared")

# Create a singleton instance
_key_vault_client = None

def get_key_vault_client() -> KeyVaultClient:
    """Get or create the singleton Key Vault client instance."""
    global _key_vault_client
    if _key_vault_client is None:
        _key_vault_client = KeyVaultClient()
    return _key_vault_client

@lru_cache(maxsize=32)
def get_secret(secret_name: str, default_env_var: Optional[str] = None) -> Optional[str]:
    """
    Convenience function to retrieve a secret from the Key Vault.

    Args:
        secret_name: Name of the secret in Key Vault
        default_env_var: Environment variable name to use as fallback

    Returns:
        Secret value or None if not found
    """
    client = get_key_vault_client()
    return client.get_secret(secret_name, default_env_var)

def set_secret(secret_name: str, secret_value: str) -> Tuple[bool, str]:
    """
    Convenience function to set a secret in the Key Vault and return identifier.

    Args:
        secret_name: Name of the secret in Key Vault
        secret_value: Value of the secret

    Returns:
        Tuple of (success_status, secret_identifier_or_error)
    """
    client = get_key_vault_client()
    return client.set_secret(secret_name, secret_value)

def get_secret_by_id(secret_id: str) -> Optional[str]:
    """
    Convenience function to retrieve a secret by identifier.

    Args:
        secret_id: Full secret identifier URL

    Returns:
        Secret value or None if not found
    """
    client = get_key_vault_client()
    return client.get_secret_by_id(secret_id)

def list_secrets() -> List[str]:
    """
    List all secrets in the Key Vault.

    Returns:
        List of secret names
    """
    client = get_key_vault_client()
    return client.list_secrets()

def delete_secret(secret_name: str) -> bool:
    """
    Delete a secret from the Key Vault (soft delete).

    Args:
        secret_name: Name of the secret to delete

    Returns:
        Success status (True/False)
    """
    client = get_key_vault_client()
    return client.delete_secret(secret_name)

# Specific secret retrieval functions for common credentials
def get_rpc_url() -> Optional[str]:
    """Get the Alchemy RPC URL."""
    # Assuming the secret is named 'alchemy-rpc-url' in Key Vault
    return get_secret('alchemy-rpc-url', 'ALCHEMY_RPC_URL')

def get_api_key() -> Optional[str]:
    """Get the Alchemy API key."""
    # Assuming the secret is named 'alchemy-api-key' in Key Vault
    return get_secret('alchemy-api-key', 'ALCHEMY_API_KEY')

def get_wallet_credential() -> Optional[str]:
    """Get the wallet credential."""
    # Assuming the secret is named 'wallet-private-key' in Key Vault
    return get_secret('wallet-private-key', 'WALLET_PRIVATE_KEY')

def get_azure_client_id() -> Optional[str]:
    """Get the Azure client ID."""
    # Assuming the secret is named 'azure-client-id' in Key Vault
    return get_secret('azure-client-id', 'AZURE_CLIENT_ID')

def get_azure_app_id() -> Optional[str]:
    """Get the Azure app ID."""
    # Assuming the secret is named 'azure-app-id' in Key Vault
    return get_secret('azure-app-id', 'AZURE_APP_ID')

def get_azure_client_secret() -> Optional[str]:
    """Get the Azure client secret."""
    # Assuming the secret is named 'azure-client-secret' in Key Vault
    return get_secret('azure-client-secret', 'AZURE_CLIENT_SECRET')

def get_azure_tenant_id() -> Optional[str]:
    """Get the Azure tenant ID."""
    return get_secret('azure-tenant-id', 'AZURE_TENANT_ID')

def get_azure_subscription_id() -> Optional[str]:
    """Get the Azure subscription ID."""
    return get_secret('azure-subscription-id', 'AZURE_SUBSCRIPTION_ID')

def get_azure_keyvault_uri() -> Optional[str]:
    """Get the Azure Key Vault URI."""
    return get_secret('azure-keyvault-uri', 'AZURE_KEYVAULT_URI')

def get_azure_keyvault_name() -> Optional[str]:
    """Get the Azure Key Vault name."""
    return get_secret('azure-keyvault-name', 'AZURE_KEYVAULT_NAME')

def get_azure_resource_group_resource_id() -> Optional[str]:
    """Get the Azure resource group resource ID."""
    return get_secret('azure-resource-group-resource-id', 'AZURE_RESOURCE_GROUP_RESOURCE_ID')

def get_alchemy_app_id() -> Optional[str]:
    """Get the Alchemy app ID."""
    return get_secret('alchemy-app-id', 'ALCHEMY_APP_ID')

def get_alchemy_mainnet_key_id() -> Optional[str]:
    """Get the Alchemy mainnet key ID."""
    return get_secret('alchemy-mainnet-key-id', 'ALCHEMY_MAINNET_KEY_ID')

def get_alchemy_rpc_url_mainnet() -> Optional[str]:
    """Get the Alchemy RPC URL for mainnet."""
    return get_secret('alchemy-rpc-url-mainnet', 'ALCHEMY_RPC_URL_MAINNET')

def get_flashbots_alchemy_rpc_url_sepolia() -> Optional[str]:
    """Get the Flashbots Alchemy RPC URL for Sepolia."""
    return get_secret('flashbots-alchemy-rpc-url-sepolia', 'FLASHBOTS_ALCHEMY_RPC_URL_SEPOLIA')

def get_flashbots_alchemy_rpc_url_mainnet() -> Optional[str]:
    """Get the Flashbots Alchemy RPC URL for mainnet."""
    return get_secret('flashbots-alchemy-rpc-url-mainnet', 'FLASHBOTS_ALCHEMY_RPC_URL_MAINNET')

def get_flashbots_signing_key_address() -> Optional[str]:
    """Get the Flashbots signing key address."""
    return get_secret('flashbots-signing-key-address', 'FLASHBOTS_SIGNING_KEY_ADDRESS')

def get_flashbots_signing_key() -> Optional[str]:
    """Get the Flashbots signing key."""
    return get_secret('flashbots-signing-key', 'FLASHBOTS_SIGNING_KEY')

def get_flashbots_builder_rpc_url_sepolia() -> Optional[str]:
    """Get the Flashbots builder RPC URL for Sepolia."""
    return get_secret('flashbots-builder-rpc-url-sepolia', 'FLASHBOTS_BUILDER_RPC_URL_SEPOLIA')

def get_flashbots_rpc_url_mainnet() -> Optional[str]:
    """Get the Flashbots RPC URL for mainnet."""
    return get_secret('flashbots-rpc-url-mainnet', 'FLASHBOTS_RPC_URL_MAINNET')

def get_dune_api_key() -> Optional[str]:
    """Get the Dune API key."""
    return get_secret('dune-api-key', 'DUNE_API_KEY')

def get_dune_api_request_timeout() -> Optional[str]:
    """Get the Dune API request timeout."""
    return get_secret('dune-api-request-timeout', 'DUNE_API_REQUEST_TIMEOUT')

# Functions for initializing and testing key vault
def init_from_env() -> List[Tuple[str, bool]]:
    """
    Initialize Key Vault secrets from environment variables, only creating missing ones.

    Returns:
        List of (secret_name, success) tuples
    """
    logger.info("Checking vault for existing secrets")

    # Get existing secrets first
    existing_secrets = list_secrets()
    logger.info(f"Found {len(existing_secrets)} existing secrets in vault")

    secrets_to_set = [
        ('alchemy-rpc-url', 'ALCHEMY_RPC_URL'),
        ('alchemy-api-key', 'ALCHEMY_API_KEY'),
        ('wallet-private-key', 'WALLET_PRIVATE_KEY'),
        ('azure-client-id', 'AZURE_CLIENT_ID'),
        ('azure-app-id', 'AZURE_APP_ID'),
        ('azure-client-secret', 'AZURE_CLIENT_SECRET'),
        ('alchemy-app-id', 'ALCHEMY_APP_ID'),
        ('alchemy-mainnet-key-id', 'ALCHEMY_MAINNET_KEY_ID'),
        ('alchemy-rpc-url-mainnet', 'ALCHEMY_RPC_URL_MAINNET'),
        ('flashbots-alchemy-rpc-url-sepolia', 'FLASHBOTS_ALCHEMY_RPC_URL_SEPOLIA'),
        ('flashbots-alchemy-rpc-url-mainnet', 'FLASHBOTS_ALCHEMY_RPC_URL_MAINNET'),
        ('flashbots-signing-key-address', 'FLASHBOTS_SIGNING_KEY_ADDRESS'),
        ('flashbots-signing-key', 'FLASHBOTS_SIGNING_KEY'),
        ('flashbots-builder-rpc-url-sepolia', 'FLASHBOTS_BUILDER_RPC_URL_SEPOLIA'),
        ('flashbots-rpc-url-mainnet', 'FLASHBOTS_RPC_URL_MAINNET'),
        ('dune-api-key', 'DUNE_API_KEY'),
        ('dune-api-request-timeout', 'DUNE_API_REQUEST_TIMEOUT'),
        ('azure-tenant-id', 'AZURE_TENANT_ID'),
        ('azure-subscription-id', 'AZURE_SUBSCRIPTION_ID'),
        ('azure-keyvault-uri', 'AZURE_KEYVAULT_URI'),
        ('azure-keyvault-name', 'AZURE_KEYVAULT_NAME'),
        ('azure-resource-group-resource-id', 'AZURE_RESOURCE_GROUP_RESOURCE_ID')
    ]

    results = []
    created_count = 0

    for i, (secret_name, env_var) in enumerate(secrets_to_set, 1):
        if secret_name in existing_secrets:
            logger.info(f"Secret {i} of {len(secrets_to_set)} already exists")
            results.append((secret_name, True))
            continue

        # Secret doesn't exist, create it
        env_value = os.getenv(env_var)
        if not env_value:
            logger.warning(f"Environment variable for secret {i} of {len(secrets_to_set)} not set, skipping")
            results.append((secret_name, False))
            continue

        logger.info(f"Creating missing secret {i} of {len(secrets_to_set)}")
        success, identifier_or_error = set_secret(secret_name, env_value)
        results.append((secret_name, success))

        if success:
            created_count += 1
            logger.info(f"Created secret {i} of {len(secrets_to_set)}")

    logger.info(f"Configuration: created {created_count} new secrets")
    return results

def test_secrets() -> List[Tuple[str, bool]]:
    """
    Test retrieval of secrets from Key Vault without fallback to environment.

    Returns:
        List of (secret_name, success) tuples
    """
    secrets_to_test = [
        ('alchemy-rpc-url', None),
        ('alchemy-api-key', None),
        ('wallet-private-key', None),
        ('azure-client-id', None),
        ('azure-app-id', None),
        ('azure-client-secret', None),
        ('alchemy-app-id', None),
        ('alchemy-mainnet-key-id', None),
        ('alchemy-rpc-url-mainnet', None),
        ('flashbots-alchemy-rpc-url-sepolia', None),
        ('flashbots-alchemy-rpc-url-mainnet', None),
        ('flashbots-signing-key-address', None),
        ('flashbots-signing-key', None),
        ('flashbots-builder-rpc-url-sepolia', None),
        ('flashbots-rpc-url-mainnet', None),
        ('dune-api-key', None),
        ('dune-api-request-timeout', None),
        ('azure-tenant-id', None),
        ('azure-subscription-id', None),
        ('azure-keyvault-uri', None),
        ('azure-keyvault-name', None),
        ('azure-resource-group-resource-id', None)
    ]

    results = []
    client = get_key_vault_client()
    success_count = 0

    logger.info("Testing secret retrieval")
    for i, (secret_name, _) in enumerate(secrets_to_test, 1):
        logger.info(f"Testing secret {i} of {len(secrets_to_test)}")

        # Test direct retrieval without fallback to environment variables
        value = client.get_secret(secret_name, None)
        success = value is not None
        results.append((secret_name, success))

        if success:
            success_count += 1
            logger.info(f"Successfully retrieved secret {i} of {len(secrets_to_test)}")
        else:
            logger.warning(f"Failed to retrieve secret {i} of {len(secrets_to_test)}")

    logger.info(f"Secret testing: {success_count}/{len(secrets_to_test)} secrets retrieved")
    return results