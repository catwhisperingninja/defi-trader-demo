# Demo DeFi Trader – Uniswap Trading Bot

A Python-based, bare-bones demo DeFi trading application that monitors Uniswap V3 pools on the Sepolia testnet, collects price data, calculates multiple technical indicators, and applies some secret-sauce trading logic to determine whether to execute a buy, sell, or nothing.

No on-testnet-chain transactions are executed. It's just logs flying by.

This is my way of proving that the private repo actually exists.

---

## Features

- Real-time pool information fetched from the Sepolia network through Alchemy RPC URL
- Token price data from Alchemy Price API
- EMA-12, EMA-26, MACD, signal indicator calculations + execution threshold calculation
- Continuous logging of market state and buy/sell signals with which to populate future database for backtesting
- Configured for the Poetry package manager

---

## Start

### Create Your Own .gitignore
Standard Python is fine. You'll want to ignore *.json and *.log, and of course .env and .venv although those should likely pre-populate.

### price_history.json File
Create a file named exactly "price_history.json" at root level of project.
Place this in your own .gitignore file as it will get huge.
You don't _have_ to do this, I suppose.

### Sign Up with Alchemy for API Access
#### This, you must do.
https://www.alchemy.com/
- Free. They make this easy. Love you, Alchemy. Nice work.
- Create an app, name it whatever. Enable the *SEPOLIA* RPC endpoints. NOT the mainnet ETH ones, as well as the Prices API, Token API, and whatever else you feel like.
- Take note of your APP ID. This is NOT your API key. You still need it.
- Grab a NEW ETH browser extension crypto wallet, (*NEW!* Yes, because you don't want this privkey associated with any of your actual funds. This is a demo.)
- Set wallet to SEPOLIA testnet, google "Alchemy Sepolia testnet ETH faucet", and Alchemy's faucet is easy to find from there. Send yourself at least 0.5 testnet ETH.
- Any other method of obtaining Sepolia testnet ETH is a total pain. Feel free to explore.

### Required .env Environment Variables


| Variable            | Purpose                                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------------------------|
| `ALCHEMY_RPC_URL`   | HTTPS RPC endpoint for the Sepolia test network                                                           |
| `ALCHEMY_API_KEY`   | Alchemy Price Feeds API key                                                                               |
| `WALLET_PRIVATE_KEY`| Used on the backend to display wallet balance (the key itself is **never** printed or logged, _see disclaimer at end_)             |


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
Ensure you have Python3.11 or above installed first.
```curl -sSL https://install.python-poetry.org | python3 -```

#### Poetry Config Essentials
If you haven't used Poetry before:
```poetry config --list ```
Usually not much you have to change here; the terminal will warn you if there is.
Consider turning off ```pip``` usage if you have ```pip``` installed. Especially if you are on Mac and use Homebrew for Python installations.

##### pyproject.toml File Setup
- Open this at project root level.
- There is a [tool.poetry] section. Modify this line like so:
```package-mode = false```
- You MUST do this, or the Poetry dependencies won't install.
- In the same section, modify the authors line:
```authors = ["your_alias <whatever-email.com>"]```
- Your authors line MUST be in that EXACT format, and PRESENT. (Yes, with the <> around the email, that is meant literally here.) Or, same result. Won't work.
- This project has a .toml ready to go for you. If you want to play with the code and add new Python modules, you must run:
```poetry add <module>```
- Then proceed as below.

### Install Project Dependencies with Poetry

```bash
# 1. Install dependencies (Poetry is required)
poetry lock
poetry install

# If you're running this in 2030, try:
poetry update # this will update all dependencies to their latest versions

# 3. Run the continuous monitoring script
poetry run python uni_handler.py
```

## How It Works

1. `uni_handler.py` instantiates `UniswapTrading` from `pydantic_trader_main.py`, then creates a `UniswapPoolAnalyzer` for each configured pool.
2. Every cycle (default: 5 s) it:
   - Fetches the latest token price via the Alchemy Price API.
   - Queries the selected Uniswap V3 pool for liquidity, price data, etc.
   - Updates the local `price_history.json` cache.
   - Calculates EMA-12, EMA-26, MACD & Signal-line, and many other things in the full version.
   - Logs BUY / SELL recommendations when bullish or bearish patterns emerge.
3. No Ethereum transactions are signed or broadcast.

---

## Disclaimers

1. Production repo includes a far larger feature set: gas fee analysis, standardized calculation methods, Flashbots, etc.
2. Still debugging Azure Key Vault for secure secret management due to persistent issues with a critical dependency upgrade breaking the Azure CLI.
3. Production repo contains extensive test suite.
4. Math here is acknowledged as a mess; I know, it's been fixed on the production repo.
5. You must immediately convert all price API reponses to wei and calculate as an integer on the backend.
6. The Prices API is solid. But if you're running a trading app, you want realtime data fast fast fast. Dune Analytics will do that for you, but you need to run actual SQL queries, not use the prices query ID. That query is 1 hour behind.
7. Human-readable numbers are only intended for the demo logging console that this repo runs.

Enjoy the logs.

---

## License

MIT – see the `LICENSE` file for details.
