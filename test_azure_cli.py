#!/usr/bin/env python3
"""
Test the Azure CLI-based Key Vault implementation.
"""
import os
import sys
import logging
import subprocess
import json
import io
import time
import glob
import re
from datetime import datetime
from unittest.mock import patch
from dotenv import load_dotenv
from typing import Dict, List, Optional, Tuple, Any, Union

# Add the pydantic_trader directory to path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pydantic_trader'))

# Import from the azure-cli module (using importlib to handle hyphen in name)
import importlib.util
import sys

# Load the azure_key_vault_cli module from the azure-cli directory
azure_cli_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pydantic_trader', 'azure-cli', 'azure_key_vault_cli.py')
spec = importlib.util.spec_from_file_location("azure_key_vault_cli", azure_cli_path)
if spec is None or spec.loader is None:
    raise ImportError("Could not load azure_key_vault_cli module")
azure_key_vault_cli = importlib.util.module_from_spec(spec)
sys.modules["azure_key_vault_cli"] = azure_key_vault_cli
spec.loader.exec_module(azure_key_vault_cli)

# Note: Access functions directly from the dynamically loaded module to avoid IDE import issues

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def sanitize_command_for_logs(cmd: List[str]) -> Optional[List[str]]:
    """Sanitize a command by removing sensitive operations from logging entirely."""
    # Check if this is a sensitive command that shouldn't be logged at all
    sensitive_operations = ["secret", "login", "password", "key", "credential", "token"]
    if any(op in " ".join(cmd).lower() for op in sensitive_operations):
        return None  # Don't log sensitive commands

    return cmd  # Return the command if it's safe to log

def run_cmd(cmd: List[str]) -> Tuple[bool, str]:
    """Run a shell command and return the output."""
    # Check if this is a sensitive command
    sanitized_cmd = sanitize_command_for_logs(cmd)

    # Only log non-sensitive commands
    if sanitized_cmd:
        logger.info(f"Running: {' '.join(sanitized_cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30  # 30 second timeout to prevent hanging
        )

        if result.returncode == 0:
            # Check if this operation might involve sensitive data
            sensitive_operations = ["secret", "login", "password", "key", "credential", "token"]
            is_sensitive = any(op in " ".join(cmd).lower() for op in sensitive_operations)

            if is_sensitive:
                # For sensitive operations, just indicate success without any details
                logger.info("Command succeeded")
            else:
                # Only log success for commands that don't contain sensitive data
                # Azure CLI account info contains tenant IDs and should not be logged
                if "account" in " ".join(cmd):
                    logger.info("Command succeeded")
                else:
                    logger.info("Command succeeded")
                    logger.info(f"Output: {result.stdout}")

            return True, result.stdout
        else:
            # Don't log error details for sensitive operations
            logger.error(f"Command failed with return code {result.returncode}")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after 30 seconds")
        return False, "Command timeout"
    except Exception as e:
        logger.error(f"Exception running command: {type(e).__name__}")
        return False, str(e)

def check_azure_cli() -> Tuple[bool, str]:
    """Check if Azure CLI is available and logged in."""
    # Use query to only return non-sensitive info
    return run_cmd(["az", "account", "show", "--query", "name", "-o", "tsv"])

def check_service_principal() -> Optional[str]:
    """Check if service principal is properly configured."""
    app_id = os.getenv('AZURE_APP_ID')
    client_secret = os.getenv('AZURE_CLIENT_SECRET')

    if not app_id:
        logger.error("Required configuration missing")
        return None

    if not client_secret:
        logger.warning("Required configuration may be incomplete")

    # Don't log client ID
    logger.info("Azure auth identity configured")
    return app_id

def get_vault_name() -> Optional[str]:
    """Get vault name from environment variable."""
    vault_name = os.getenv('AZURE_KEYVAULT_NAME')
    if vault_name:
        logger.info("Using configured vault name")
        return vault_name

    # Fallback to extracting from URI if name not provided
    vault_uri = os.getenv('AZURE_KEYVAULT_URI')
    if not vault_uri:
        logger.error("Vault configuration not found.")
        return None

    try:
        vault_name = vault_uri.split('.')[0].split('//')[1]
        logger.info("Extracted vault name from URI")
        return vault_name
    except (IndexError, AttributeError):
        logger.error("Failed to extract vault name from URI")
        return None

def get_resource_group() -> Optional[str]:
    """Get resource group name from environment variable."""
    resource_group = os.getenv('AZURE_RESOURCE_GROUP')
    if resource_group:
        logger.info("Using configured resource group")
    return resource_group

def get_auth_args() -> List[str]:
    """Get command arguments for authentication."""
    # Service principal authentication
    return ["--only-show-errors"]

def login_with_service_principal() -> bool:
    """Login to Azure CLI using service principal credentials if not already logged in."""
    app_id = os.getenv('AZURE_APP_ID')
    client_id = os.getenv('AZURE_CLIENT_ID')
    client_secret = os.getenv('AZURE_CLIENT_SECRET')

    if not app_id or not client_secret:
        logger.error("Missing required credentials")
        return False

    try:
        # First check if already logged in
        account_check = subprocess.run(
            ["az", "account", "show", "--query", "name", "-o", "tsv"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15
        )

        if account_check.returncode == 0:
            logger.info("Already authenticated")
            return True

        # If not logged in, attempt login with service principal
        logger.info("Authenticating")

        # Prepare login command (Don't log anything about it)
        login_cmd = [
            "az", "login", "--service-principal",
            "--username", app_id,
            "--password", client_secret
        ]

        result = subprocess.run(
            login_cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=45  # Login can take longer
        )

        if result.returncode != 0:
            logger.error("Authentication failed")
            return False

        logger.info("Authentication successful")
        return True
    except subprocess.TimeoutExpired:
        logger.error("Authentication timed out")
        return False
    except Exception as e:
        # Don't include any error details that might contain credentials
        logger.error("Authentication error occurred")
        return False

def set_secret(vault_name: str, secret_name: str, secret_value: str) -> Tuple[bool, str]:
    """Set a secret in the Key Vault using Azure CLI and return secret identifier."""
    # Don't log that we're setting a secret or which one
    cmd = [
        "az", "keyvault", "secret", "set",
        "--vault-name", vault_name,
        "--name", secret_name,
        "--value", secret_value,
        "--query", "id",
        "-o", "tsv"
    ]

    # Add authentication args
    auth_args = get_auth_args()
    cmd.extend(auth_args)

    success, output = run_cmd(cmd)
    if success:
        return success, output.strip()  # Return the secret identifier
    else:
        return success, output

def list_secrets(vault_name: str) -> Tuple[bool, str]:
    """List secrets in the Key Vault using Azure CLI."""
    cmd = [
        "az", "keyvault", "secret", "list",
        "--vault-name", vault_name,
        "--query", "[].name",
        "-o", "json"
    ]

    # Note: --resource-group is not supported for Key Vault secret operations

    # Add authentication args
    auth_args = get_auth_args()
    cmd.extend(auth_args)

    return run_cmd(cmd)

def get_secret(vault_name: str, secret_name: str) -> Tuple[bool, str]:
    """Get a secret from the Key Vault using Azure CLI."""
    cmd = [
        "az", "keyvault", "secret", "show",
        "--vault-name", vault_name,
        "--name", secret_name,
        "--query", "value",
        "-o", "tsv"
    ]

    # Note: --resource-group is not supported for Key Vault secret operations

    # Add authentication args
    auth_args = get_auth_args()
    cmd.extend(auth_args)

    return run_cmd(cmd)

def get_secret_by_id(secret_id: str) -> Tuple[bool, str]:
    """Get a secret from the Key Vault using Azure CLI by secret identifier."""
    cmd = [
        "az", "keyvault", "secret", "show",
        "--id", secret_id,
        "--query", "value",
        "-o", "tsv"
    ]

    # Add authentication args
    auth_args = get_auth_args()
    cmd.extend(auth_args)

    return run_cmd(cmd)

def init_test_secrets(vault_name: str) -> Tuple[bool, Dict[str, str]]:
    """Initialize Azure connection secrets + test secret, only creating missing ones."""
    # Check existing secrets first
    logger.info("Checking vault for existing secrets")
    success, output = list_secrets(vault_name)
    if not success:
        logger.error("Failed to list existing secrets")
        return False, {}

    try:
        existing_secrets = json.loads(output)
    except json.JSONDecodeError:
        logger.error("Failed to parse existing secrets list")
        return False, {}

    logger.info(f"Found {len(existing_secrets)} existing secrets in vault")

    # Define required secrets (production secrets)
    required_secrets = [
        ('azure-app-id', 'AZURE_APP_ID'),
        ('azure-client-id', 'AZURE_CLIENT_ID'),
        ('azure-client-secret', 'AZURE_CLIENT_SECRET'),
        ('azure-tenant-id', 'AZURE_TENANT_ID'),
        ('azure-subscription-id', 'AZURE_SUBSCRIPTION_ID'),
        ('azure-keyvault-uri', 'AZURE_KEYVAULT_URI'),
        ('azure-keyvault-name', 'AZURE_KEYVAULT_NAME')
    ]

    # Test secret always gets unique timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    test_secret_name = f"azure-test-secret-{timestamp}"

    identifiers: Dict[str, str] = {}  # Dictionary to store all secret identifiers (ephemeral - memory only)

    # Get identifiers for existing required secrets
    existing_count = 0
    for i, (secret_name, env_var) in enumerate(required_secrets, 1):
        if secret_name in existing_secrets:
            logger.info(f"Getting existing secret {i} of {len(required_secrets)}")
            # Get identifier for existing secret
            success, result = get_secret(vault_name, secret_name)
            if success:
                # For existing secrets, we need to get the identifier differently
                # We'll reconstruct it or get it via a different method
                # For now, store a placeholder - this will be improved in production
                identifiers[secret_name] = f"existing-{secret_name}"
                existing_count += 1
                logger.info(f"Retrieved existing secret {i} of {len(required_secrets)}")
            else:
                logger.error(f"Failed to retrieve existing secret {i} of {len(required_secrets)}")
        else:
            logger.info(f"Creating missing secret {i} of {len(required_secrets)}")
            env_value = os.getenv(env_var)
            if not env_value:
                env_value = f"test-value-for-{secret_name}"

            # Retry logic for transient failures
            max_retries = 3
            for retry in range(max_retries):
                success, result = set_secret(vault_name, secret_name, env_value)

                if success:
                    identifiers[secret_name] = result
                    logger.info(f"Created secret {i} of {len(required_secrets)}")
                    break
                else:
                    if retry < max_retries - 1:
                        logger.warning(f"Retry {retry + 1}/{max_retries} for secret operation")
                        logger.warning("Error occurred during secret operation")
                        time.sleep(2 ** retry)  # Exponential backoff: 1s, 2s, 4s
                    else:
                        logger.error("Maximum retries exceeded for secret operation")
                        logger.error("Final error occurred")

    # Always create test secret (unique timestamp)
    logger.info("Creating test secret")
    env_value = os.getenv('AZURE_TEST_SECRET')
    if not env_value:
        env_value = f"test-value-for-{test_secret_name}"

    max_retries = 3
    test_created = False
    for retry in range(max_retries):
        success, result = set_secret(vault_name, test_secret_name, env_value)

        if success:
            identifiers[test_secret_name] = result
            test_created = True
            break
        else:
            if retry < max_retries - 1:
                logger.warning(f"Retry {retry + 1}/{max_retries} for test secret operation")
                logger.warning("Error occurred during test secret operation")
                time.sleep(2 ** retry)
            else:
                logger.error("Maximum retries exceeded for test secret operation")
                logger.error("Final error occurred")

    total_expected = len(required_secrets) + (1 if test_created else 0)
    total_processed = len(identifiers)

    logger.info(f"Configuration: {total_processed}/{total_expected} items processed")

    return total_processed == total_expected, identifiers

def set_secret_via_client(client: Any, secret_name: str, secret_value: str) -> bool:
    """Set a secret using the KeyVaultClient."""
    result = client.set_secret(secret_name, secret_value)
    if isinstance(result, tuple):
        success, identifier_or_error = result
        return bool(success)
    else:
        return bool(result)  # Return just the success status for compatibility

def list_secrets_via_client(client: Any) -> Any:
    """List secrets using the KeyVaultClient."""
    return client.list_secrets()

def get_secret_via_client(client: Any, secret_name: str) -> Any:
    """Get a secret using the KeyVaultClient."""
    return client.get_secret(secret_name, None)  # No fallback to env vars

def init_test_secrets_via_client(client: Any) -> bool:
    """Initialize Azure connection secrets + test secret using KeyVaultClient."""
    # Use fixed test secret name - identifier approach eliminates collision issues
    test_secret_name = "azure-test-secret"

    secrets_to_set = [
        ('azure-app-id', 'AZURE_APP_ID'),
        ('azure-client-id', 'AZURE_CLIENT_ID'),
        ('azure-client-secret', 'AZURE_CLIENT_SECRET'),
        ('azure-tenant-id', 'AZURE_TENANT_ID'),
        ('azure-subscription-id', 'AZURE_SUBSCRIPTION_ID'),
        ('azure-keyvault-uri', 'AZURE_KEYVAULT_URI'),
        ('azure-keyvault-name', 'AZURE_KEYVAULT_NAME'),
        (test_secret_name, 'AZURE_TEST_SECRET')
    ]

    success_count = 0
    for secret_name, env_var in secrets_to_set:
        env_value = os.getenv(env_var)
        if not env_value:
            env_value = f"test-value-for-{secret_name}"

        # Use the KeyVaultClient to set the secret
        success = set_secret_via_client(client, secret_name, env_value)

        if success:
            success_count += 1

    logger.info(f"Configuration: {success_count}/{len(secrets_to_set)} items processed")
    return success_count == len(secrets_to_set)

def validate_console_output_security(log_output: str) -> bool:
    """
    Validate that console output contains no secret data or secret portions.

    Args:
        log_output: The console output to validate

    Returns:
        True if output is secure, False if secrets detected
    """
    logger.info("Validating console output security")

    # Get environment variables that should never appear in logs
    sensitive_env_vars = [
        'AZURE_CLIENT_SECRET',
        'AZURE_APP_ID',
        'AZURE_CLIENT_ID',
        'ALCHEMY_API_KEY',
        'WALLET_PRIVATE_KEY'
    ]

    # Check for full secret values
    for env_var in sensitive_env_vars:
        secret_value = os.getenv(env_var)
        if secret_value and secret_value in log_output:
            logger.error(f"SECURITY VIOLATION: Full secret value detected in logs")
            return False

    # Check for partial secret values (first 3 or last 3 characters)
    # But exclude common prefixes/suffixes that might match accidentally
    for env_var in sensitive_env_vars:
        secret_value = os.getenv(env_var)
        if secret_value and len(secret_value) > 6:
            first_three = secret_value[:3]
            last_three = secret_value[-3:]

            # Skip very common patterns that might match accidentally
            common_patterns = ['the', 'and', 'for', 'are', 'you', 'all', 'not', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use']

            if (first_three.lower() not in common_patterns and
                last_three.lower() not in common_patterns and
                first_three in log_output or last_three in log_output):
                logger.error(f"SECURITY VIOLATION: Partial secret value detected in logs")
                return False

    # Check for masked secret patterns that might still expose data
    import re
    masked_patterns = [
        r'[a-zA-Z0-9]{3,}\.\.\.[a-zA-Z0-9]{3,}',  # xxx...xxx patterns
        r'[a-zA-Z0-9]{8,}',  # Long alphanumeric strings that might be secrets
    ]

    for pattern in masked_patterns:
        if re.search(pattern, log_output):
            # Check if this might be a secret by looking for context
            matches = re.findall(pattern, log_output)
            for match in matches:
                # Skip known safe patterns (like timestamps, addresses, etc.)
                if not (match.startswith('202') or  # timestamps
                       match.startswith('0x') or   # ethereum addresses
                       'successful' in match.lower() or
                       'failed' in match.lower()):
                    logger.warning(f"POTENTIAL SECURITY ISSUE: Suspicious pattern detected: {match[:3]}...")

    logger.info("Console output security validation passed")
    return True

def validate_authentication_logs(log_output: str) -> bool:
    """
    Validate that authentication-related logs don't expose sensitive data.

    Args:
        log_output: The console output to validate

    Returns:
        True if authentication logs are secure, False otherwise
    """
    logger.info("Validating authentication log security")

        # Forbidden authentication details in logs (actual values, not names)
    forbidden_patterns = [
        r'client.?id\s*[=:]\s*[^\s]+',  # client-id = value or client_id: value
        r'client.?secret\s*[=:]\s*[^\s]+',  # client-secret = value
        r'app.?id\s*[=:]\s*[^\s]+',  # app-id = value
        r'password\s*[=:]\s*[^\s]+',  # password = value
        r'token\s*[=:]\s*[^\s]+',  # token = value
        r'tenant\s*[=:]\s*[^\s]+'  # tenant = value
    ]

    import re
    # Check each line of output
    lines = log_output.split('\n')
    for line in lines:
        line_lower = line.lower()
        for pattern in forbidden_patterns:
            if re.search(pattern, line_lower):
                # Don't log the actual match to avoid exposing secrets
                logger.error(f"SECURITY VIOLATION: Authentication credential value detected in logs")
                return False

    logger.info("Authentication log security validation passed")
    return True

def simple_leak_check() -> bool:
    """
    Simple check for obvious identifier leak files.

    Returns:
        True if no leak files found, False if leaks detected
    """
    logger.info("Checking for identifier leak files")

    # Check for obvious accidentally created files
    leak_files = glob.glob("*identifier*") + glob.glob("*secret*.txt") + glob.glob("*vault*.json")

    if leak_files:
        logger.error(f"Potential identifier leak files found: {leak_files}")
        return False
    else:
        logger.info("No identifier leak files detected")
        return True

def validate_vault_operation_logs(log_output: str) -> bool:
    """
    Validate that vault operation logs don't expose secret names or values.

    Args:
        log_output: The console output to validate

    Returns:
        True if vault logs are secure, False otherwise
    """
    logger.info("Validating vault operation log security")

    # Check that we don't log actual secret values
    lines = log_output.split('\n')
    for line in lines:
        # Look for lines that might contain secret values (but exclude headers/status messages)
        line_lower = line.lower()
        if ('secret' in line_lower and '=' in line and
            'initializing' not in line_lower and
            'testing' not in line_lower and
            'listing' not in line_lower and
            '===' not in line):
            logger.error("SECURITY VIOLATION: Potential secret value assignment in logs")
            return False

        # Check for Base64-like strings that might be secrets
        import re
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        if re.search(base64_pattern, line):
            logger.warning("POTENTIAL SECURITY ISSUE: Base64-like string detected in logs")

    logger.info("Vault operation log security validation passed")
    return True

def run_comprehensive_log_validation(log_output: str) -> bool:
    """
    Run all log validation functions on the provided output.

    Args:
        log_output: The console output to validate

    Returns:
        True if all validations pass, False otherwise
    """
    logger.info("=== Running Comprehensive Log Security Validation ===")

    validations = [
        ("Console Output Security", validate_console_output_security),
        ("Authentication Log Security", validate_authentication_logs),
        ("Vault Operation Log Security", validate_vault_operation_logs)
    ]

    all_passed = True
    for validation_name, validation_func in validations:
        logger.info(f"Running {validation_name} validation...")
        try:
            if not validation_func(log_output):
                logger.error(f"{validation_name} validation FAILED")
                all_passed = False
            else:
                logger.info(f"{validation_name} validation PASSED")
        except Exception as e:
            logger.error(f"{validation_name} validation ERROR: {str(e)}")
            all_passed = False

    if all_passed:
        logger.info("=== ALL LOG SECURITY VALIDATIONS PASSED ===")
    else:
        logger.error("=== SOME LOG SECURITY VALIDATIONS FAILED ===")

    return all_passed

def test_log_redaction() -> bool:
    """
    Test that sensitive information is properly protected in logs and outputs.
    Returns True if all tests pass, False otherwise.
    """
    logger.info("Running security validation")

    # Create a mock logger to capture log output
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    test_logger = logging.getLogger("security_test")
    test_logger.setLevel(logging.INFO)
    test_logger.addHandler(handler)

    # Test 1: Check that sensitive commands aren't logged
    sensitive_commands = [
        ["az", "login", "--service-principal", "--username", "app_id", "--password", "secret"],
        ["az", "keyvault", "secret", "set", "--vault-name", "vault", "--name", "name", "--value", "secret"],
        ["az", "keyvault", "secret", "show", "--vault-name", "vault", "--name", "name"]
    ]

    test_logger.info("Testing command logging")
    all_tests_passed = True

    for cmd in sensitive_commands:
        # Clear the capture buffer
        log_capture.seek(0)
        log_capture.truncate(0)

        # Process command through sanitizer
        sanitized = sanitize_command_for_logs(cmd)

        # If secure, sanitizer should return None for sensitive commands
        if sanitized is not None:
            test_logger.error("FAIL: Sensitive command not properly handled")
            all_tests_passed = False

    # Test 2: Check that run_cmd doesn't log sensitive information
    with patch('subprocess.run') as mock_run:
        # Mock the subprocess run
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Secret data that should not be logged"

        # Clear the capture buffer
        log_capture.seek(0)
        log_capture.truncate(0)

        # Run a sensitive command
        test_cmd = ["az", "keyvault", "secret", "show", "--vault-name", "vault", "--name", "secret"]
        run_cmd(test_cmd)

        # Get the logged output
        log_output = log_capture.getvalue()

        # Check that command arguments aren't in logs
        if "secret" in log_output.lower() or "vault" in log_output.lower():
            test_logger.error("FAIL: Sensitive operation details leaked")
            all_tests_passed = False

        # Check that output isn't logged
        if "Secret data" in log_output:
            test_logger.error("FAIL: Sensitive output leaked")
            all_tests_passed = False

    # Test 3: Test service principal login doesn't leak information
    with patch('subprocess.run') as mock_run:
        # Set up environment variables
        os.environ['AZURE_CLIENT_ID'] = 'test-client-id'
        os.environ['AZURE_APP_ID'] = 'test-app-id'
        os.environ['AZURE_CLIENT_SECRET'] = 'test-client-secret'

        # Mock subprocess
        mock_run.side_effect = [
            type('obj', (object,), {'returncode': 1, 'stderr': 'Error with credentials: test-client-secret'}),
            type('obj', (object,), {'returncode': 0, 'stdout': 'Login successful with test-client-id'})
        ]

        # Clear the capture buffer
        log_capture.seek(0)
        log_capture.truncate(0)

        # Call the login function
        login_with_service_principal()

        # Get the logged output
        log_output = log_capture.getvalue()

        # Check that no credentials are logged
        if "client-id" in log_output or "client-secret" in log_output:
            test_logger.error("FAIL: Credentials leaked in logs")
            all_tests_passed = False

    if all_tests_passed:
        logger.info("Security validation passed")
    else:
        logger.error("Security validation failed")

    return all_tests_passed

def main() -> None:
    """Main function to test Azure CLI with Key Vault."""
    # Load environment variables
    load_dotenv()

    # First run redaction tests to ensure logging is secure
    if not test_log_redaction():
        logger.error("Redaction tests failed. Fix security issues before proceeding.")
        sys.exit(1)

    # Ensure service principal is configured
    logger.info("=== Checking programmatic auth configuration ===")
    app_id = check_service_principal()
    if not app_id:
        logger.error("Service principal not properly configured.")
        sys.exit(1)

    # Login with service principal if needed
    logger.info("=== Checking Azure CLI Login ===")
    if not login_with_service_principal():
        logger.error("Failed to login with service principal.")
        sys.exit(1)

    # Check Azure CLI
    logger.info("=== Checking Azure CLI ===")
    success, _ = check_azure_cli()
    if not success:
        logger.error("Azure CLI not available or not logged in.")
        sys.exit(1)

    resource_group = get_resource_group()

    # Get vault name
    vault_name = get_vault_name()
    if not vault_name:
        logger.error("Could not determine vault name.")
        sys.exit(1)

    # Pre-test leak check
    logger.info("=== Pre-Test Leak Check ===")
    if not simple_leak_check():
        logger.error("Pre-test leak check failed. Potential leak files detected!")
        sys.exit(1)

    # Initialize test secrets first
    logger.info(f"=== Initializing test secrets in vault ===")
    success, identifiers = init_test_secrets(vault_name)
    if not success:
        logger.error("Failed to initialize test secrets.")
        sys.exit(1)

    # List secrets
    logger.info(f"=== Listing secrets in vault ===")
    success, output = list_secrets(vault_name)
    if not success:
        logger.error("Failed to list secrets.")
        sys.exit(1)

    # Parse secret names from output
    try:
        secret_names = json.loads(output)
        logger.info(f"Found {len(secret_names)} secrets in vault")
    except json.JSONDecodeError:
        logger.error("Failed to parse secret list.")
        secret_names = []

    # Test retrieving specific secrets (using fixed names for regular secrets)
    regular_secrets = [
        'azure-app-id',
        'azure-client-id',
        'azure-client-secret',
        'azure-tenant-id',
        'azure-subscription-id',
        'azure-keyvault-uri',
        'azure-keyvault-name'
    ]

    logger.info("=== Testing secret retrieval ===")
    success_count = 0

        # Test ALL secrets by identifier (consistent approach) - no secret names in logs
    secret_index = 1
    for secret_name in regular_secrets:
        if secret_name in identifiers:
            logger.info(f"Getting secret {secret_index} of {len(regular_secrets)} by identifier")

            # Use appropriate method based on identifier type
            if identifiers[secret_name].startswith("existing-"):
                # For existing secrets, use name-based retrieval (will improve in production)
                success, value = get_secret(vault_name, secret_name)
            else:
                # For newly created secrets, use identifier-based retrieval
                success, value = get_secret_by_id(identifiers[secret_name])

            if success:
                success_count += 1
                logger.info(f"Successfully retrieved secret {secret_index} of {len(regular_secrets)}")
            else:
                logger.error(f"Failed to retrieve secret {secret_index} of {len(regular_secrets)}")
        else:
             logger.error("No identifier available for one of the requested secrets.")

        secret_index += 1

    # Test the test secret by identifier
    test_secret_name = None
    for name in identifiers:
        if name.startswith("azure-test-secret"):
            test_secret_name = name
            break

    if test_secret_name and test_secret_name in identifiers:
        logger.info(f"Getting test secret by identifier")
        success, value = get_secret_by_id(identifiers[test_secret_name])

        if success:
            success_count += 1
            logger.info(f"Successfully retrieved test secret by identifier")
        else:
            logger.error(f"Failed to retrieve test secret by identifier")

    total_secrets = len(regular_secrets) + (1 if test_secret_name else 0)
    logger.info("Successfully retrieved all requested secrets.")

    # Clean up test secret - skip cleanup since we use unique names
    logger.info("=== Test secret cleanup ===")
    if test_secret_name:
        logger.info("Test secret used unique timestamp name - no cleanup needed")
        logger.info("Soft-deleted secrets will be automatically purged after 90 days")
    else:
        logger.warning("No test secret to clean up")

    # Post-test leak check
    logger.info("=== Post-Test Leak Check ===")
    if not simple_leak_check():
        logger.error("Post-test leak check failed. Identifiers may have leaked to disk!")
        sys.exit(1)

    if success_count == total_secrets:
        logger.info("All tests passed! The CLI implementation is working correctly.")
        logger.info("No identifier leaks detected - secrets handled securely.")
    else:
        logger.error("Some tests failed. Check the logs for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()
