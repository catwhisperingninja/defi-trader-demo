# Setup Guide

Complete installation and configuration instructions for the DeFi Trading Bot.

## Prerequisites

Ensure you have Python 3.11 installed.

## Sign Up with Alchemy for API Access

https://www.alchemy.com/

- Free. They make this easy. Love you, Alchemy. Nice work.
- Create an app. Enable the _SEPOLIA_ RPC endpoints. NOT the mainnet ETH ones,
  as well as the Prices API, Token API, etc., as desired.
- Take note of your APP ID, which is NOT your API key. Both are required.
- Grab a NEW ETH browser extension crypto wallet
  - (_NEW!_ Yes, because you don't want this privkey associated with any of your
    actual funds. This is a demo.)
- Set wallet to SEPOLIA testnet
  - Google "Alchemy Sepolia testnet ETH faucet"
  - The wallet in this repo is hardcoded for 0.15 testnet ETH to trade, but
    we're not trading. You just need a balance there.

## Required .env Environment Variables

| Variable             | Purpose                                                                                                                |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `ALCHEMY_RPC_URL`    | HTTPS RPC endpoint for the Sepolia test network                                                                        |
| `ALCHEMY_API_KEY`    | Alchemy Price Feeds API key                                                                                            |
| `ALCHEMY_APP_ID`     | Alchemy App ID                                                                                                         |
| `WALLET_PRIVATE_KEY` | Used on the backend to display wallet balance (the key itself is **never** printed or logged, _see disclaimer at end_) |

## Poetry Package Manager Installation

### Install Poetry

`curl -sSL https://install.python-poetry.org | python3 -`

### Poetry Config Essentials

If you haven't used Poetry before:

`poetry config --list`

Usually not much you have to change here; the terminal will warn you if there
is. Consider turning off `pip` usage if you have `pip` installed.

Especially if you are on Mac and use Homebrew for Python installations.

### pyproject.toml File Setup

- Open this at project root level.
- There is a [tool.poetry] section. Modify this line like so:
  `package-mode = false`
- In the same section, modify the authors line:
  `authors = ["your_alias <whatever-email.com>"]`
- This project has a .toml ready to go.
- Then proceed as below.

## Install Project Dependencies

### Azure KeyVault Functions Using Secret Identifiers Now Included

```bash
# 1. Install dependencies (Poetry is required)
poetry lock
poetry install
```

### If you're running this in 2030, try:

```bash
poetry update
```

This will update all dependencies to their latest versions.

## Running the Application

```bash
# Run the continuous monitoring script
poetry run python uni_handler.py
```

## Create Your Own .gitignore

Standard Python is fine. You'll want to ignore `*.json` and `*.log`, and of
course `.env` and `.venv`.
