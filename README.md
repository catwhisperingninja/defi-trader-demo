# Demo DeFi Trading Bot

A Python-based, bare-bones demo DeFi arbitrage application that monitors Uniswap
V3 pools on the Sepolia testnet, collects price data, calculates multiple
technical indicators, and applies some secret-sauce trading logic to determine
whether to execute a buy, sell, or do nothing.

No on-testnet-chain transactions are executed. It's just logs flying by.

This is my way of proving that the private repo actually exists.

## Quick Start

1. **Prerequisites**: Python 3.11 and Poetry package manager
2. **Install**: `poetry install`
3. **Configure**: Set up your `.env` file with Alchemy credentials
4. **Run**: `poetry run python uni_handler.py`

## Documentation

- **[Setup Guide](docs/SETUP.md)** - Detailed installation and configuration
- **[Azure KeyVault Setup](docs/AZURE_KEYVAULT.md)** - Enterprise security
  management
- **[Trading Guide](docs/TRADING_GUIDE.md)** - How the bot works and features
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Known limitations and fixes

## Features

- Real-time price monitoring via Alchemy API
- Technical indicator calculations (EMA-12, EMA-26, MACD)
- Uniswap V3 pool analysis on Sepolia testnet
- Azure KeyVault integration for secure credential management
- Comprehensive logging for strategy backtesting

## License

MIT – see the `LICENSE` file for details.
