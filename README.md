# DeFi Trader – Uniswap Analysis Bot

A Python-based, bare-bones demo DeFi trading application that monitors Uniswap V3 pools on the Sepolia testnet, collects price data, calculates multiple technical indicators, and applies some secret-sauce trading logic to determine whether to execute a buy, sell, or nothing.
No on-testnet-chain transactions are executed.
---

## Features

• Real-time pool information fetched from the Sepolia network through Alchemy RPC
• Token price data from Alchemy Price Feeds
• EMA-12, EMA-26, MACD, signal indicator calculations + execution threshold calculation
• Continuous logging of market state and buy/sell signals with which to populate future database for backtesting
• Stand-alone command-line execution – no additional services required
• Configured for the Poetry package manager

---

## Quick Start

```bash
# 1. Install dependencies (Poetry is required)
poetry lock
poetry install

# 3. Run the continuous monitoring script
poetry run python uni_handler.py
```

### Required Environment Variables


| Variable            | Purpose                                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------------------------|
| `ALCHEMY_RPC_URL`   | HTTPS RPC endpoint for the Sepolia test network                                                           |
| `ALCHEMY_API_KEY`   | Alchemy Price Feeds API key                                                                               |
| `WALLET_PRIVATE_KEY`| Used on the backend to display wallet balance (the key itself is **never** printed or logged)             |

If `WALLET_PRIVATE_KEY` is omitted, the bot generates a temporary account and stays in **read-only** mode.

---

## Repository Structure (relevant files)

```
├── uni_handler.py           # Main loop: fetch prices, calculate indicators
├── pydantic_trader_main.py  # Helper class wrapping Web3 + contract ABIs
├── uniswap_abis.json        # ABI bundle required by pydantic_trader_main.py
├── price_history.json       # Rolling cache of recent prices (auto-created)
└── pyproject.toml           # Poetry configuration
```

---

## How It Works

1. `uni_handler.py` instantiates `UniswapTrading` from `pydantic_trader_main.py`, then creates a `UniswapPoolAnalyzer` for each configured pool.
2. Every cycle (default: 5 s) it:
   • Fetches the latest token price via the Alchemy Price API.
   • Queries the selected Uniswap V3 pool for liquidity, price data, etc.
   • Updates the local `price_history.json` cache.
   • Calculates EMA-12, EMA-26, MACD & Signal-line.
   • Logs BUY / SELL recommendations when bullish or bearish patterns emerge.
3. No Ethereum transactions are signed or broadcast.

---

## Disclaimers

1. Production branch includes a far larger feature set: gas fee analysis, standardized calculation methods, Flashbots, etc.
2. Still debugging Azure Key Vault for secure secret management due to persistent issues with a critical dependency upgrade breaking the Azure CLI.
3. Production branch contains extensive test suite.
4. Math is acknowledged to be a mess; it's been fixed on the production repo. Must immediately convert all price API reponses to wei and calculate as an integer on the backend. Human-readable numbers are only intended for the demo logging console that this repo runs.

> ⚠️  The current repository intentionally omits any code path that can move money on-chain.

---

## License

MIT – see the `LICENSE` file for details.
