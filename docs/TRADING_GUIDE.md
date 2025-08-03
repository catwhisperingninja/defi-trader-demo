# Trading Guide

## Repository Structure (relevant files)

```
├── uni_handler.py           # Main loop: fetch prices, calculate indicators
├── pydantic_trader_main.py  # Helper class wrapping Web3 + contract ABIs
├── uniswap_abis.json        # ABI bundle required by pydantic_trader_main.py
├── price_history.json       # Rolling cache of recent prices (auto-created)
└── pyproject.toml           # Poetry configuration
```

## How It Works

1. `uni_handler.py` instantiates `UniswapTrading` from
   `pydantic_trader_main.py`, then creates a `UniswapPoolAnalyzer` for each
   configured pool.
2. Every cycle (default: 5 s) it:
   - Fetches the latest token price via the Alchemy Price API.
   - Queries the selected Uniswap V3 pool for liquidity, price data, etc.
   - Updates the local `price_history.json` cache.
   - Calculates EMA-12, EMA-26, MACD & Signal-line, and many other things in the
     full version.
   - Logs BUY / SELL recommendations when bullish or bearish patterns emerge.
3. No Ethereum transactions are signed or broadcast.

## Features

- Real-time data fetched from ETH mainnet via Alchemy API (production repo uses
  Dune Analytics)
- EMA-12, EMA-26, MACD, signal indicator calculations + execution threshold
  calculation via Alchemy API
- Continuous logging of market state and buy/sell signals with which to populate
  future database for backtesting
- Configured for the Poetry package manager

## Azure KeyVault Integration

Azure KeyVault now included! See [Azure KeyVault Setup](AZURE_KEYVAULT.md) for
setup instructions.

This integration provides enterprise-grade security for managing sensitive
credentials and API keys.
