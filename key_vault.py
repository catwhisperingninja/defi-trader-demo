"""
Secure credential management module.
"""
import os
import sys
import importlib.util

# Handle the hyphen in directory name by using direct file path loading
azure_cli_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pydantic_trader', 'azure-cli', 'azure_key_vault_cli.py')
spec = importlib.util.spec_from_file_location("azure_key_vault_cli", azure_cli_path)
key_vault_module = importlib.util.module_from_spec(spec)
sys.modules["azure_key_vault_cli_key_vault"] = key_vault_module
spec.loader.exec_module(key_vault_module)

# Re-export all the functions and classes
get_secret = key_vault_module.get_secret
set_secret = key_vault_module.set_secret
get_secret_by_id = key_vault_module.get_secret_by_id
list_secrets = key_vault_module.list_secrets
delete_secret = key_vault_module.delete_secret
get_key_vault_client = key_vault_module.get_key_vault_client
get_rpc_url = key_vault_module.get_rpc_url
get_api_key = key_vault_module.get_api_key
get_wallet_credential = key_vault_module.get_wallet_credential
get_azure_client_id = key_vault_module.get_azure_client_id
get_azure_app_id = key_vault_module.get_azure_app_id
get_azure_client_secret = key_vault_module.get_azure_client_secret
get_azure_tenant_id = key_vault_module.get_azure_tenant_id
get_azure_subscription_id = key_vault_module.get_azure_subscription_id
get_azure_keyvault_uri = key_vault_module.get_azure_keyvault_uri
get_azure_keyvault_name = key_vault_module.get_azure_keyvault_name
get_azure_resource_group_resource_id = key_vault_module.get_azure_resource_group_resource_id
get_alchemy_app_id = key_vault_module.get_alchemy_app_id
get_alchemy_mainnet_key_id = key_vault_module.get_alchemy_mainnet_key_id
get_alchemy_rpc_url_mainnet = key_vault_module.get_alchemy_rpc_url_mainnet
get_flashbots_alchemy_rpc_url_sepolia = key_vault_module.get_flashbots_alchemy_rpc_url_sepolia
get_flashbots_alchemy_rpc_url_mainnet = key_vault_module.get_flashbots_alchemy_rpc_url_mainnet
get_flashbots_signing_key_address = key_vault_module.get_flashbots_signing_key_address
get_flashbots_signing_key = key_vault_module.get_flashbots_signing_key
get_flashbots_builder_rpc_url_sepolia = key_vault_module.get_flashbots_builder_rpc_url_sepolia
get_flashbots_rpc_url_mainnet = key_vault_module.get_flashbots_rpc_url_mainnet
get_dune_api_key = key_vault_module.get_dune_api_key
get_dune_api_request_timeout = key_vault_module.get_dune_api_request_timeout
init_from_env = key_vault_module.init_from_env
test_secrets = key_vault_module.test_secrets
KeyVaultClient = key_vault_module.KeyVaultClient

__all__ = [
    'get_secret',
    'set_secret',
    'get_secret_by_id',
    'list_secrets',
    'delete_secret',
    'get_key_vault_client',
    'get_rpc_url',
    'get_api_key',
    'get_wallet_credential',
    'get_azure_client_id',
    'get_azure_app_id',
    'get_azure_client_secret',
    'get_azure_tenant_id',
    'get_azure_subscription_id',
    'get_azure_keyvault_uri',
    'get_azure_keyvault_name',
    'get_azure_resource_group_resource_id',
    'get_alchemy_app_id',
    'get_alchemy_mainnet_key_id',
    'get_alchemy_rpc_url_mainnet',
    'get_flashbots_alchemy_rpc_url_sepolia',
    'get_flashbots_alchemy_rpc_url_mainnet',
    'get_flashbots_signing_key_address',
    'get_flashbots_signing_key',
    'get_flashbots_builder_rpc_url_sepolia',
    'get_flashbots_rpc_url_mainnet',
    'get_dune_api_key',
    'get_dune_api_request_timeout',
    'init_from_env',
    'test_secrets',
    'KeyVaultClient'
]