# Troubleshooting & Known Limitations

## Known Limitations

1. Private production repo includes a far larger feature set: gas fee analysis,
   standardized calculation methods, Flashbots, etc.
2. Production repo also contains extensive test suite.
3. Math here is acknowledged as a flat-out wrong mess; I know, it's fixed on the
   production repo.
4. The Prices API is solid. But if you're running a trading app, you want
   realtime data fast fast fast. Dune Analytics will do that for you, but you
   need to run actual SQL via their API, not use the prices query ID. That query
   is 1 hour behind.
5. Human-readable numbers are only intended for the demo logging console that
   this repo runs. Blockchain math is handled using wei-level integers and Dune
   Analytics operations on the API response.
6. Please take the time to read the [Azure KeyVault Setup](AZURE_KEYVAULT.md) to
   understand secret management.

## Important Notes

- No on-testnet-chain transactions are executed. It's just logs flying by.
- This is a demo-only DeFi arbitrage application illustrating application
  development skills while keeping my private production repo private.

## Common Issues

### Environment Variables

Make sure all required environment variables are set in your `.env` file:

- `ALCHEMY_RPC_URL`
- `ALCHEMY_API_KEY`
- `ALCHEMY_APP_ID`
- `WALLET_PRIVATE_KEY`

### Network Configuration

Ensure your wallet and RPC endpoints are configured for **Sepolia testnet**, not
mainnet.

### Dependencies

If you encounter dependency issues, try:

```bash
poetry update
```
