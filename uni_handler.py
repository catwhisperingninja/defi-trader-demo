import numpy as np
from typing import Dict, List, Tuple, Optional
import logging
from decimal import Decimal
import asyncio
import os
import aiohttp
from dotenv import load_dotenv
from web3 import Web3
import time
import json
import sys
import signal

from pydantic_trader_main import UniswapTrading

logger = logging.getLogger(__name__)

class TechnicalIndicators:
    @staticmethod
    def calculate_ema(data: List[float], period: int) -> List[float]:
        """
        Calculate Exponential Moving Average with robust error handling

        Args:
            data: List of price data
            period: EMA calculation period

        Returns:
            List of EMA values
        """
        try:
            if len(data) < period:
                raise ValueError(f"Insufficient data. Need at least {period} data points.")

            ema = []
            multiplier = 2 / (period + 1)

            # First EMA uses SMA as initial value
            sma = sum(data[:period]) / period
            ema.append(sma)

            for price in data[period:]:
                ema.append((price - ema[-1]) * multiplier + ema[-1])

            return ema
        except Exception as e:
            logger.error(f"EMA calculation failed: {e}")
            raise

    @staticmethod
    def calculate_macd(
        data: List[float],
        fast_period: int = 12,
        slow_period: int = 26,
        signal_period: int = 9
    ) -> Tuple[List[float], List[float]]:
        """
        Calculate MACD and Signal line with robust error handling

        Args:
            data: List of price data
            fast_period: Fast EMA period
            slow_period: Slow EMA period
            signal_period: Signal line period

        Returns:
            Tuple of MACD line and Signal line
        """
        try:
            if len(data) < slow_period + signal_period:
                raise ValueError(f"Insufficient data. Need at least {slow_period + signal_period} data points.")

            fast_ema = TechnicalIndicators.calculate_ema(data, fast_period)
            slow_ema = TechnicalIndicators.calculate_ema(data, slow_period)

            # Calculate MACD line
            macd_line = [fast - slow for fast, slow in zip(fast_ema[slow_period-fast_period:], slow_ema)]

            # Calculate Signal line
            signal_line = TechnicalIndicators.calculate_ema(macd_line, signal_period)

            return macd_line, signal_line
        except Exception as e:
            logger.error(f"MACD calculation failed: {e}")
            raise

class UniswapPoolAnalyzer:
    def __init__(self, trading_instance: UniswapTrading):
        """
        Initialize Uniswap Pool Analyzer

        Args:
            trading_instance: UniswapTrading instance
        """
        self.trading = trading_instance
        self.price_histories: Dict[str, List[float]] = {}  # Map token address to its price history
        self.indicators = TechnicalIndicators()
        self.price_history_file = "price_history.json"

        # Initialize price oracle
        self.api_key = os.getenv('ALCHEMY_API_KEY')
        if not self.api_key:
            raise RuntimeError("ALCHEMY_API_KEY environment variable is required")
        self.base_url = f"https://api.g.alchemy.com/prices/v1/{self.api_key}"

        # Token address to symbol mapping (all lowercase)
        self.token_symbols = {
            "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": "UNI",  # UNI
            "0x7b79995e5f793a07bc00c21412e50ecae098e7f9": "ETH",  # WETH
            "0x8267cf9254734c6eb452a7bb9aaf97b392258b21": "USDC",  # USDC
        }

        # Load saved price history if available
        self.load_price_history()

    def save_price_history(self):
        """Save price histories to JSON file"""
        try:
            # Convert price histories to serializable format
            history_data = {
                token: {
                    'symbol': self.token_symbols.get(token, 'UNKNOWN'),
                    'prices': prices,
                    'last_updated': time.time()
                }
                for token, prices in self.price_histories.items()
            }

            with open(self.price_history_file, 'w') as f:
                json.dump(history_data, f, indent=2)

            logger.info(f"Saved price history to {self.price_history_file}")
        except Exception as e:
            logger.error(f"Failed to save price history: {e}")

    def load_price_history(self):
        """Load price histories from JSON file if it exists"""
        try:
            if not os.path.exists(self.price_history_file):
                logger.info("No saved price history found")
                return

            with open(self.price_history_file, 'r') as f:
                history_data = json.load(f)

            # Check if data is too old (more than 1 hour)
            current_time = time.time()
            max_age = 3600  # 1 hour in seconds

            for token, data in history_data.items():
                if current_time - data.get('last_updated', 0) > max_age:
                    logger.info(f"Saved price history for {data['symbol']} is too old, skipping")
                    continue

                self.price_histories[token] = data['prices']
                logger.info(f"Loaded {len(data['prices'])} price points for {data['symbol']}")

        except Exception as e:
            logger.error(f"Failed to load price history: {e}")
            # Initialize empty if load fails
            self.price_histories = {}

    async def get_token_price(self, token_symbol: str) -> Optional[Dict]:
        """
        Get token price from Alchemy Price Feeds API using symbol

        Args:
            token_symbol: Token symbol (e.g. 'UNI', 'ETH')

        Returns:
            Price information dictionary or None on failure
        """
        try:
            headers = {"accept": "application/json"}
            url = f"{self.base_url}/tokens/by-symbol?symbols={token_symbol}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Price API error {response.status}")
                        return None

                    data = await response.json()
                    if not data or not data.get('data'):
                        return None

                    token_data = data['data'][0]
                    if not token_data.get('prices'):
                        return None

                    price_data = token_data['prices'][0]
                    return {
                        'price': float(price_data['value']),
                        'currency': price_data['currency'].upper(),
                        'timestamp': time.time(),
                        'last_updated': price_data['lastUpdatedAt']
                    }

        except Exception as e:
            logger.warning(f"Price fetch failed: {e}")
            return None

    async def update_market_state(self, token0: str, token1: str, fee: int = 3000, pool_address: Optional[str] = None) -> Optional[Dict]:
        """
        Update market state with pool information and technical indicators

        Args:
            token0: First token address
            token1: Second token address
            fee: Pool fee tier
            pool_address: Optional specific pool address to use

        Returns:
            Market state dictionary or None
        """
        try:
            # Convert to checksum addresses
            token0_checksum = Web3.to_checksum_address(token0)
            token1_checksum = Web3.to_checksum_address(token1)

            logger.info(f"Updating market state for {token0_checksum}/{token1_checksum}")

            # Initialize price history for this token if not exists
            if token0_checksum.lower() not in self.price_histories:
                self.price_histories[token0_checksum.lower()] = []

            # If pool address is provided, use it directly
            if pool_address:
                pool_address_checksum = Web3.to_checksum_address(pool_address)

                # Create contract instance
                contract = self.trading.w3.eth.contract(
                    address=pool_address_checksum,
                    abi=self.trading.abis['UniswapV3Pool']['abi']
                )

                try:
                    # Try to retrieve pool details
                    slot0 = contract.functions.slot0().call()
                    liquidity = contract.functions.liquidity().call()

                    # Calculate price from sqrt_price_x96
                    sqrt_price_x96 = slot0[0]
                    tick = slot0[1]
                    price = (sqrt_price_x96 ** 2) / (2 ** 192)

                    pool_status = {
                        'address': pool_address_checksum,
                        'price': price,
                        'tick': tick,
                        'liquidity': liquidity,
                        'fee_tier': fee
                    }

                except Exception as contract_error:
                    logger.warning(
                        f"Pool address {pool_address_checksum} failed: {contract_error}. "
                        "Attempting factory lookup instead."
                    )

                    # Fallback to factory lookup
                    pool_status = await self.trading.check_pool_status(
                        token0_checksum, token1_checksum, [fee]
                    )

                    if not pool_status:
                        logger.error("Factory lookup did not return a valid pool address")
                        return None

            # If no pool address or retrieval failed, try finding pool
            else:
                # Get current pool status
                pool_status = await self.trading.check_pool_status(token0_checksum, token1_checksum, [fee])

                if not pool_status:
                    logger.warning(f"No pool found for {token0_checksum}/{token1_checksum}")
                    return None

            # Try to fetch token prices
            try:
                # Get token symbol from address mapping
                token0_symbol = self.token_symbols.get(token0_checksum.lower())
                if not token0_symbol:
                    logger.warning(f"No symbol mapping for token {token0_checksum}")
                    return None

                token_price = await self.get_token_price(token0_symbol)
                if token_price:
                    price_history = self.price_histories[token0_checksum.lower()]
                    price_history.append(token_price['price'])
                    logger.info(f"{token0_symbol} Price: ${token_price['price']} {token_price['currency']}")

                    # Keep last 100 prices for indicators
                    if len(price_history) > 100:
                        self.price_histories[token0_checksum.lower()] = price_history[-100:]

                    # Save updated price history
                    self.save_price_history()

            except Exception as price_error:
                logger.warning(f"Price fetch error: {price_error}")

            # Calculate technical indicators if we have enough data
            price_history = self.price_histories[token0_checksum.lower()]
            market_state = {
                **pool_status,
                'price_history': price_history
            }

            # Add technical indicators if enough data
            if len(price_history) >= 26:
                try:
                    macd_line, signal_line = self.indicators.calculate_macd(price_history)
                    ema_12 = self.indicators.calculate_ema(price_history, 12)[-1]
                    ema_26 = self.indicators.calculate_ema(price_history, 26)[-1]

                    market_state.update({
                        'ema_12': ema_12,
                        'ema_26': ema_26,
                        'macd': macd_line[-1] if macd_line else 0,
                        'signal': signal_line[-1] if signal_line else 0
                    })
                    logger.info(f"Calculated indicators for {token0_symbol}:")
                    logger.info(f"  EMA 12: {ema_12:.8f}")
                    logger.info(f"  EMA 26: {ema_26:.8f}")
                    logger.info(f"  MACD: {macd_line[-1]:.8f}")
                    logger.info(f"  Signal: {signal_line[-1]:.8f}")
                except Exception as e:
                    logger.error(f"Failed to calculate indicators: {e}")
            else:
                logger.info(f"Not enough price data yet. Have {len(price_history)}, need 26.")

            return market_state

        except Exception as e:
            logger.error(f"Market state update failed: {e}")
            return None

class TradingStrategy:
    def __init__(self, pool_analyzer: UniswapPoolAnalyzer):
        """
        Initialize Trading Strategy

        Args:
            pool_analyzer: UniswapPoolAnalyzer instance
        """
        self.pool_analyzer = pool_analyzer
        self.trail_percent = 0.02  # 2% trailing stop

    async def analyze_signals(self, market_state: Dict) -> List[Dict]:
        """
        Analyze market signals and generate trading actions

        Args:
            market_state: Current market state dictionary

        Returns:
            List of trading actions
        """
        try:
            actions = []

            logger.info(f"Signal Analysis Parameters:")
            logger.info(f"  EMA 12: {market_state.get('ema_12', 'N/A')}")
            logger.info(f"  EMA 26: {market_state.get('ema_26', 'N/A')}")
            logger.info(f"  MACD: {market_state.get('macd', 'N/A')}")
            logger.info(f"  Signal: {market_state.get('signal', 'N/A')}")

            # Check for bullish signal
            if (market_state.get('ema_12', 0) > market_state.get('ema_26', 0) and
                market_state.get('macd', 0) > market_state.get('signal', 0)):
                logger.info("Bullish Signal Detected!")
                actions.append({
                    'action': 'buy',
                    'size': 1.0,
                    'trail_percent': self.trail_percent
                })

            # Check for bearish signal
            elif (market_state.get('ema_12', 0) < market_state.get('ema_26', 0) and
                  market_state.get('macd', 0) < market_state.get('signal', 0)):
                logger.info("Bearish Signal Detected!")
                actions.append({
                    'action': 'sell',
                    'size': 1.0,
                    'trail_percent': self.trail_percent
                })
            else:
                logger.info("No Clear Trading Signal")

            return actions

        except Exception as e:
            logger.error(f"Signal analysis failed: {e}")
            return []

# Add main block to demonstrate usage
async def main():
    """
    Demonstrate UniswapPoolAnalyzer and TradingStrategy functionality
    """
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    # Load environment variables
    load_dotenv()

    try:
        # Import here to avoid circular import
        from pydantic_trader_main import UniswapTrading

        # Use environment variable for private key
        private_key = os.getenv('WALLET_PRIVATE_KEY')

        # Initialize trading setup
        trader = UniswapTrading(private_key)

        # Create pool analyzer
        pool_analyzer = UniswapPoolAnalyzer(trader)

        # Create trading strategy
        trading_strategy = TradingStrategy(pool_analyzer)

        # Pools to investigate
        pools = [
            {
                'token0': "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",  # UNI
                'token1': "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9",  # WETH
                'pool_address': "0x287B0e934ed0439E2a7b1d5F0FC25eA2c24b64f7",  # UNI/ETH 0.3% pool
                'name': 'UNI/ETH 0.3% Pool'
            },
            {
                'token0': "0x8267cF9254734C6Eb452a7bb9AAF97B392258b21",  # USDC
                'token1': "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9",  # WETH
                'pool_address': "0x6Ce0896eAE6D4BD668fDe41BB784548fb8F59b50",  # USDC/ETH 0.3% pool
                'name': 'USDC/ETH 0.3% Pool'
            }
        ]

        # Required points for technical analysis
        required_points = 35  # 26 for slow EMA + 9 for signal line
        logger.info(f"Starting continuous price monitoring. Need {required_points} initial points for technical analysis.")

        iteration = 0
        while True:  # Run continuously
            iteration += 1
            logger.info(f"\n--- Market State Update Iteration {iteration} ---")
            if iteration <= required_points:
                logger.info(f"Building initial dataset ({iteration}/{required_points})")

            # Use asyncio.gather to process pools concurrently
            pool_tasks = []
            for pool in pools:
                task = asyncio.create_task(process_pool(pool, pool_analyzer, trading_strategy))
                pool_tasks.append(task)

            try:
                # Wait for all pool processing tasks to complete
                await asyncio.gather(*pool_tasks)
            except RuntimeError as e:
                logger.error(f"Price fetch failed: {e}")
                # Don't exit on error, just skip this iteration
                continue
            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt, shutting down...")
                break

            # Wait between iterations to avoid rate limits
            # Adjust this based on how often you want to check prices
            await asyncio.sleep(5)  # Check every 5 seconds

    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)  # Exit with error code

async def process_pool(pool: Dict, pool_analyzer, trading_strategy):
    """
    Process a single pool

    Args:
        pool: Pool configuration dictionary
        pool_analyzer: UniswapPoolAnalyzer instance
        trading_strategy: TradingStrategy instance
    """
    logger = logging.getLogger(__name__)

    logger.info(f"\n--- Investigating {pool['name']} ---")

    # Analyze market state
    logger.info("Analyzing market state...")
    try:
        market_state = await pool_analyzer.update_market_state(
            token0=pool['token0'],
            token1=pool['token1'],
            pool_address=pool['pool_address']
        )

        if not market_state:
            logger.error(f"Failed to retrieve market state for {pool['name']}")
            return  # Continue with other pools instead of exiting

        logger.info("Market State Details:")
        logger.info(f"Pool Address: {market_state.get('address', pool['pool_address'])}")
        logger.info(f"Current Price: {market_state.get('price', 'N/A')}")
        logger.info(f"Current Tick: {market_state.get('tick', 'N/A')}")
        logger.info(f"Current Liquidity: {market_state.get('liquidity', 'N/A')}")

        # Analyze trading signals
        logger.info("Analyzing trading signals...")
        trading_actions = await trading_strategy.analyze_signals(market_state)

        if trading_actions:
            logger.info("Trading Actions:")
            for action in trading_actions:
                logger.info(f"Action: {action['action']}")
                logger.info(f"Size: {action['size']}")
                logger.info(f"Trailing Stop: {action['trail_percent'] * 100}%")
        else:
            logger.info("No trading actions recommended.")
    except Exception as e:
        logger.error(f"Error processing pool {pool['name']}: {e}")
        return  # Continue with other pools instead of exiting

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    # Perform any necessary cleanup here
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

try:
    # Your main script logic here
    asyncio.run(main())
except KeyboardInterrupt:
    print('You pressed Ctrl+C!')
    # Perform any necessary cleanup here
    sys.exit(0)