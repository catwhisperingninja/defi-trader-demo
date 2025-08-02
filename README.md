# Demo DeFi Trading Bot

A Python-based, bare-bones demo DeFi arbitrage application that monitors Uniswap
V3 pools on the Sepolia testnet, collects price data, calculates multiple
technical indicators, and applies some secret-sauce trading logic to determine
whether to execute a buy, sell, or do nothing.

No on-testnet-chain transactions are executed. It's just logs flying by.

Azure KeyVault now included! See
[AZURE_KEYVAULT_README.md](AZURE_KEYVAULT_README.md) for setup instructions.

This is my way of proving that the private repo actually exists.

---

## Features

- Real-time data fetched from ETH mainnet via Dune Analytics
- EMA-12, EMA-26, MACD, signal indicator calculations + execution threshold
  calculation
- Continuous logging of market state and buy/sell signals with which to populate
  future database for backtesting
- Configured for the Poetry package manager

---

## Start

### Create Your Own .gitignore

Standard Python is fine. You'll want to ignore _.json and _.log, and of course
.env and .venv.

### Sign Up with Alchemy for API Access

https://www.alchemy.com/

- Free. They make this easy. Love you, Alchemy. Nice work.
- Create an app. Enable the _SEPOLIA_ RPC endpoints. NOT the
  mainnet ETH ones, as well as the Prices API, Token API, etc., as desired.
- Take note of your APP ID. This is NOT your API key. You still need it.
- Grab a NEW ETH browser extension crypto wallet
  - (_NEW!_ Yes, because you don't want this privkey associated with any of your actual funds. This is a demo.)
- Set wallet to SEPOLIA testnet
  - Google "Alchemy Sepolia testnet ETH faucet"
  - The wallet in this repo is hardcoded for 0.15 testnet ETH to trade, but we're not trading. You just need a balance there. 

### Required .env Environment Variables

| Variable             | Purpose                                                                                                                |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `ALCHEMY_RPC_URL`    | HTTPS RPC endpoint for the Sepolia test network                                                                        |
| `ALCHEMY_API_KEY`    | Alchemy Price Feeds API key                                                                                            |
| `WALLET_PRIVATE_KEY` | Used on the backend to display wallet balance (the key itself is **never** printed or logged, _see disclaimer at end_) |

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

## Install

### Poetry Package Manager Installer

Ensure you have Python3.11 installed. 

`curl -sSL https://install.python-poetry.org | python3 -`

#### Poetry Config Essentials

If you haven't used Poetry before:

`poetry config --list `

Usually not much you have to change here; the terminal will warn you if there
is. Consider turning off `pip` usage if you have `pip` installed.

Especially if you are on Mac and use Homebrew for Python installations.

##### pyproject.toml File Setup

- Open this at project root level.
- There is a [tool.poetry] section. Modify this line like so:
  `package-mode = false`
- In the same section, modify the authors line:
  `authors = ["your_alias <whatever-email.com>"]`
- This project has a .toml ready to go. 
- Then proceed as below.

### Install Project Dependencies with Poetry

#### Azure KeyVault Functions Using Secret Identifiers Now Included

```bash
# 1. Install dependencies (Poetry is required)
poetry lock
poetry install
```

# If you're running this in 2030, try:

```poetry update```

This will update all dependencies to their latest versions.

# 3. Run the continuous monitoring script

```
poetry run python uni_handler.py
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

---

## Disclaimers

1. Private production repo includes a far larger feature set: gas fee analysis,
   standardized calculation methods, Flashbots, etc.
2. Production repo also contains extensive test suite.
3. Math here is acknowledged as a flat-out wrong mess; I know, it's fixed on the
   production repo.
4. The Prices API is solid. But if you're running a trading app, you want
   realtime data fast fast fast. Dune Analytics will do that for you, but you
   need to run actual SQL via their API, not use the prices query ID. That query is 1
   hour behind.
5. Human-readable numbers are only intended for the demo logging console that
   this repo runs. Blockchain math is handled using wei-level integers and Dune Analytics operations on the API response. 
6. Please take the time to read the AZURE_KEYVAULT_README to understand secret
   management.

Enjoy the logs.

---

## License

MIT – see the `LICENSE` file for details.
