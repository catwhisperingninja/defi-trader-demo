# Enterprise Security Implementation

This Azure Key Vault CLI implementation features enterprise-grade security with
reference logging.

## Security Features

- **Zero secret exposure**: No secret names or values in logs (numbered
  references only)
- **Dynamic counting**: Future-proof with automatic `len()` calculations
- **Secure caching**: In-memory only, no disk persistence
- **Production-ready**: Check existing secrets first, create only missing ones
- **Service principal auth**: Minimal privilege scope per Key Vault

# Create Azure KeyVault

Self-explanatory, except for:

- Create a vnet in your target resource group (RG) with a NSG that has inbound
  SSH/RDP and HTTPS locked to only YOUR public IP address, add others as
  necessary
- Enable purge protection and soft-delete
- Choose RBAC for role management
- Vault, programmatic identities, and resource groups this vault is to interact
  with must reside in the same region; vault must reside inside target RG
- Once vault is created: Settings>Networking
- Choose "Firewalls and virtual networks", "Allow public access from specific
  virtual networks and IP addresses"
- Add the RG's main vnet
- Add your public IP address
- I consider it ok to "allow trusted M$ services to bypass firewall"

# Azure's Terrible, Horrible Programmtic Identity Auth

Short version:

- Azure only uses _managed_ identities intra-cloud.
- You cannot use a managed identity to programmatically authenticate via the
  Azure CLI from your bedroom. Cloud-only.
- You have to use a _service principal_. Which is terrible because:
  - Super old school. Like, on-prem Active Directory stuff.
  - Typically SP's are created on the Azure portal to register applications. Not
    authenticate. Merely to register them and generate a MSAL API interaction
    scope. And config SSO, and other application-things.
  - This gives SPs an APP_ID value.
  - You must use the APP_ID as the username to login via CLI.
  - But guess what? If you create the SP via the CLI, _it doesn't show in on the
    portal_. Invisible.
  - So you have to list the SPs via the CLI to find it. The APP_ID and not the
    ObjectID, as might be sensibly assumed, is the "username" for this SP.
  - SPs can be granted a frightening level of tenant-wide power.

## SPs Are One of any Azure Tenant's Main Attack Vectors

- Do not be lulled into granting this thing resource-group wide permission scope
  with some KeyVault roles and call it a day.
- This is when to obsess over least-privilege.
- ONLY give this specific KeyVault SP roles that are _scoped to 1 specific
  KeyVault in 1 specific resource group._
- Not all the KeyVaults in your tenant. 1 SP per 1 KeyVault.

## Lockdown Service Principal Permission Scope. _Tightly_.

# Login as your Service Principal

First locally set the values in your terminal:

```bash
export AZURE_APP_ID="<value>"
export AZURE_CLIENT_ID="Your OBJECT_ID value" # I know. It works.
export AZURE_CLIENT_SECRET="<value>" # Shown once when you create the SP via CLI.
export AZURE_TENANT_ID="<value>"
```

Then login as your SP:

```bash
az login --service-principal -u $AZURE_APP_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
```

### Lockdown SP Scope _ASAP_

```bash
az role assignment create --assignee-object-id <actual_ObjectID_not_APP_ID> --assignee-principal-type ServicePrincipal --scope "/subscriptions/AZURE_SUBSCRIPTION_ID/resourceGroups/AZURE_RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/AZURE_KEYVAULT_NAME"
```

Delete the SP if you're leaving your computer. It would be a drag if you left a
SP logged-in, just waiting for something to weasle in and assign itself this
nightmare:

`Azure Connected Machine Onboarding`

And over a weekend...wow. Nice global-scale Kubernetes fleet you got there. Hope
you set budget alerts!

SPs with powerful roles like that can destroy you if left unattended. Just be
aware.

## RBAC Role Definition ID Assignments

Use role definition IDs, not role names, for future-proofing.

### List KeyVault role definitions:

```bash
az role definition list --query "[?contains(roleName, 'Key Vault')].{RoleName:roleName, RoleId:name}" --output table
```

- Assign minimal required role (typically "Key Vault Secrets Reader"):

```bash
az role assignment create <actual_ObjectID_not_APP_ID> --assignee-principal-type ServicePrincipal --role-definition-id <id-value-from-list> --scope "/subscriptions/AZURE_SUBSCRIPTION_ID/resourceGroups/AZURE_RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/AZURE_KEYVAULT_NAME"
```

You'll want at least KeyVault Reader and likely both Secrets User/Officer and
Certificate User/Officer (if you wish to manage SSH keys through KeyVault, as
Azure considers them certificates. Super fun.)

You could one-up me by creating read-only SPs and write-only SPs, certainly.
This is just a demo. The SP was nuked a long time ago.

# Set up sensitive environment variables

```bash
cp .env.example .env
```

Change filename to `.env` and add the following, which already exist in your
Azure tenant, are required for SP auth and KeyVault interaction, and which will
be often used by other identities with KeyVault role assignments:

## Azure Key Vault Configuration

- `AZURE_TENANT_ID`: Your Azure tenant ID
- `AZURE_SUBSCRIPTION_ID`: Your Azure subscription ID
- `AZURE_KEYVAULT_NAME`: Name of your Azure Key Vault
- `AZURE_KEYVAULT_URI`: URI of your Azure Key Vault
- `AZURE_CLIENT_ID`: Azure service principal's Object ID value
- `AZURE_APP_ID`: Azure service principal ID (for service principal
  authentication)
- `AZURE_CLIENT_SECRET`: Azure service principal value secret (someday will
  perfect this)
- `AZURE_TENANT_ID`: Your Azure tenant ID
- `AZURE_RESOURCE_GROUP`: Azure resource group containing the Key Vault

# Test Azure Key Vault Integration

This test validates:

- **Console Output Security**: Ensures no secret values or partial secret values
  appear in logs
- **Authentication Log Security**: Verifies authentication logs don't expose
  sensitive data
- **Vault Operation Security**: Confirms vault operations don't leak secret
  names or values
- **Production Code Integration**: Tests actual Azure CLI commands and Key Vault
  operations

```bash
poetry run python test_azure_cli.py
```
## Live Example of Testing
_The SP no longer exists._ It was deleted the second I uploaded the videos. 

https://github.com/user-attachments/assets/e495d9c6-e258-4606-9191-78aefb7deed9

# Production Usage

## Initialize Azure Key Vault: First Time Production Setup

```bash
poetry run python pydantic_trader/azure-cli/initialize_key_vault_cli.py
```

https://github.com/user-attachments/assets/058c86c3-55b5-433d-ab28-37e1a29e50c9






