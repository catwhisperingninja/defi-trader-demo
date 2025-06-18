import os
import sys
import json
import asyncio
import logging
from typing import Dict, Optional, List, Any
from dotenv import load_dotenv

from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
from eth_account.signers.local import LocalAccount

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('trading.log')
    ]
)
logger = logging.getLogger(__name__)

class SepoliaConfig:
    """Configuration for Sepolia testnet"""
    def __init__(self) -> None:
        # Explicitly print out environment variables for debugging
        logger.debug("ALCHEMY_RPC_URL loaded from env")

        self.SEPOLIA_RPC_URL = os.getenv('ALCHEMY_RPC_URL')
        if not self.SEPOLIA_RPC_URL:
            logger.critical("ALCHEMY_RPC_URL environment variable not set!")
            # Provide a fallback RPC URL
            self.SEPOLIA_RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/YOUR_PROJECT_ID'
            logger.warning(f"Using fallback RPC URL: {self.SEPOLIA_RPC_URL}")

        self.CHAIN_ID = 11155111
        self.UNISWAP_V3_FACTORY = "0x0227628f3F023bb0B980b67D528571c95c6DaC1c"
        self.UNISWAP_V3_ROUTER = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"
        self.UNISWAP_V3_NFT_MANAGER = "0x1238536071E1c677A632429e3655c799b22cDA52"
        self.USDC_ADDRESS = "0x8267cF9254734C6Eb452a7bb9AAF97B392258b21"

class UniswapTrading:
    """Uniswap V3 trading implementation with robust error handling"""
    def __init__(self, private_key: Optional[str] = None):
        """
        Initialize Uniswap trading setup

        Args:
            private_key: Optional private key for the trading account
        """
        self.config = SepoliaConfig()
        self.w3 = self._initialize_web3()
        self.account = self._initialize_account(private_key)
        self._load_abis()
        self._load_contracts()

        logger.info("Trading setup initialized")

    def _initialize_web3(self) -> Web3:
        """Initialize Web3 connection with robust error handling"""
        try:
            w3 = Web3(Web3.HTTPProvider(self.config.SEPOLIA_RPC_URL))
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)

            if not w3.is_connected():
                raise ConnectionError("Failed to connect to Sepolia network")

            logger.info(f"Connected to Sepolia - Chain ID: {w3.eth.chain_id}")
            return w3
        except Exception as e:
            logger.critical(f"Web3 initialization failed: {e}")
            raise

    def _initialize_account(self, private_key: Optional[str]) -> LocalAccount:
        """
        Initialize trading account with balance check

        Args:
            private_key: Optional private key

        Returns:
            Initialized LocalAccount
        """
        try:
            if not private_key:
                logger.warning("No private key provided. Generating new account...")
                account = Account.create()
            else:
                account = Account.from_key(private_key)

            balance = self.w3.eth.get_balance(account.address)
            logger.info("Account initialized")
            logger.info(f"Balance: {self.w3.from_wei(balance, 'ether')} ETH")

            return account
        except Exception as e:
            logger.critical(f"Account initialization failed: {e}")
            raise

    def _load_abis(self) -> None:
        """Load contract ABIs with error handling"""
        try:
            with open('uniswap_abis.json', 'r') as f:
                self.abis = json.load(f)
            logger.debug("Successfully loaded contract ABIs")
        except FileNotFoundError:
            logger.critical("ABI file not found. Ensure uniswap_abis.json exists.")
            raise
        except json.JSONDecodeError:
            logger.critical("Invalid JSON in uniswap_abis.json")
            raise

    def _load_contracts(self) -> None:
        """Load Uniswap contracts with error handling"""
        try:
            self.factory = self.w3.eth.contract(
                address=self.config.UNISWAP_V3_FACTORY,
                abi=self.abis['UniswapV3Factory']['abi']
            )
            self.router = self.w3.eth.contract(
                address=self.config.UNISWAP_V3_ROUTER,
                abi=self.abis['UniswapV3Router']['abi']
            )
            logger.info("Successfully loaded Uniswap contracts")
        except Exception as e:
            logger.critical(f"Contract loading failed: {e}")
            raise

    async def check_pool_status(self, token0: str, token1: str, fee_tiers: List[int] = [3000]) -> Optional[Dict[str, Any]]:
        """
        Check Uniswap V3 pool status with Sepolia testnet fee tiers

        Args:
            token0: First token address
            token1: Second token address
            fee_tiers: List of fee tiers to check (default: [3000])

        Returns:
            Pool status details or None
        """
        # Ensure tokens are in the correct order (lower address first)
        if token1.lower() < token0.lower():
            token0, token1 = token1, token0

        logger.info(f"Searching for Uniswap V3 pool:")
        logger.info(f"Token0: {token0}")
        logger.info(f"Token1: {token1}")
        logger.info(f"Checking Sepolia testnet fee tiers: {fee_tiers}")

        # Additional verification of token addresses
        if not (Web3.is_address(token0) and Web3.is_address(token1)):
            logger.error("Invalid token addresses provided")
            return None

        for fee in fee_tiers:
            try:
                logger.info(f"Attempting to find pool with fee tier {fee} (0.{fee}%)")

                # Call getPool function with detailed logging
                try:
                    pool_address = self.factory.functions.getPool(token0, token1, fee).call()
                    logger.info(f"Pool address returned: {pool_address}")
                except Exception as pool_error:
                    logger.warning(f"getPool call failed for fee {fee}: {pool_error}")
                    continue

                if pool_address == "0x0000000000000000000000000000000000000000":
                    logger.warning(f"No pool found for {token0}/{token1} with fee {fee}")
                    continue

                # Verify the pool contract exists and can be instantiated
                try:
                    pool = self.w3.eth.contract(
                        address=pool_address,
                        abi=self.abis['UniswapV3Pool']['abi']
                    )

                    # Additional pool verification
                    try:
                        slot0 = pool.functions.slot0().call()
                        liquidity = pool.functions.liquidity().call()

                        sqrt_price_x96 = slot0[0]
                        tick = slot0[1]

                        # Detailed price calculation logging
                        price = (sqrt_price_x96 ** 2) / (2 ** 192)
                        logger.info(f"Price Calculation Details:")
                        logger.info(f"  sqrt_price_x96: {sqrt_price_x96}")
                        logger.info(f"  Calculated Price: {price}")
                        logger.info(f"  Current Tick: {tick}")
                        logger.info(f"  Current Liquidity: {liquidity}")

                        pool_status = {
                            'address': pool_address,
                            'price': price,
                            'tick': tick,
                            'liquidity': liquidity,
                            'fee_tier': fee
                        }

                        logger.info(f"Pool Status: {pool_status}")
                        return pool_status

                    except Exception as pool_data_error:
                        logger.error(f"Error retrieving pool data: {pool_data_error}")

                except Exception as contract_error:
                    logger.error(f"Error creating pool contract: {contract_error}")

            except Exception as e:
                logger.warning(f"Unexpected error checking pool with fee {fee}: {e}")

        logger.error(f"No pool found for {token0}/{token1} in any fee tier")
        return None

# ---------------------------------------------------------------------------
# Re-introduce simple shared pool configuration for other modules to import.
# Only token addresses are provided; pool_address is left None so downstream
# code can resolve via factory lookup.
# ---------------------------------------------------------------------------

DEFAULT_POOLS = [
    {
        'token0': "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",  # UNI
        'token1': "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9",  # WETH
        'pool_address': None,
        'name': 'UNI/ETH 0.3% Pool'
    },
    {
        'token0': "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",  # USDC
        'token1': "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9",  # WETH
        'pool_address': None,
        'name': 'USDC/ETH 0.3% Pool'
    }
]

async def main() -> None:
    """Main async function to demonstrate trading setup"""
    try:
        # Use environment variable for private key
        private_key = os.getenv('WALLET_PRIVATE_KEY')

        # Initialize trading setup
        trader = UniswapTrading(private_key)

        # Contracts to investigate with checksum addresses
        contracts_to_check = [
            {
                'address': Web3.to_checksum_address("0x287B0e934ed0439E2a7b1d5F0FC25eA2c24b64f7"),  # UNI/ETH 0.3% pool
                'name': 'UNI/ETH 0.3% Pool',
                'abi': 'UniswapV3Pool',
                'tokens': {
                    'token0': Web3.to_checksum_address("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"),  # UNI token
                    'token1': Web3.to_checksum_address("0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9")  # WETH token
                },
                'pool_address': None,  # Let factory lookup resolve correct pool
            },
            {
                'address': Web3.to_checksum_address("0x6Ce0896eAE6D4BD668fDe41BB784548fb8F59b50"),  # USDC/ETH 0.3% pool
                'name': 'USDC/ETH 0.3% Pool',
                'abi': 'UniswapV3Pool',
                'tokens': {
                    'token0': Web3.to_checksum_address("0x8267cF9254734C6Eb452a7bb9AAF97B392258b21"),  # USDC token
                    'token1': Web3.to_checksum_address("0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9")  # WETH token
                },
                'pool_address': None,  # Let factory lookup resolve correct pool
            }
        ]

        # Investigate each contract
        for contract_info in contracts_to_check:
            logger.info(f"\n--- Investigating {contract_info['name']} ---")
            logger.info(f"Contract Address: {contract_info['address']}")

            try:
                # Create contract instance
                contract = trader.w3.eth.contract(
                    address=contract_info['address'],
                    abi=trader.abis[contract_info['abi']]['abi']
                )

                # Attempt to retrieve basic information
                logger.info("Attempting to retrieve contract information:")

                # Check pool-specific methods for Uniswap V3 Pools
                try:
                    # Try slot0 method
                    slot0 = contract.functions.slot0().call()
                    logger.info(f"Slot0 details: {slot0}")

                    # Decode slot0 details
                    sqrt_price_x96 = slot0[0]
                    tick = slot0[1]
                    price = (sqrt_price_x96 ** 2) / (2 ** 192)

                    logger.info(f"Current Price: {price}")
                    logger.info(f"Current Tick: {tick}")

                    # Try liquidity method
                    liquidity = contract.functions.liquidity().call()
                    logger.info(f"Current Liquidity: {liquidity}")

                    # Try to get token details
                    try:
                        token0 = trader.w3.eth.contract(
                            address=contract_info['tokens']['token0'],
                            abi=trader.abis['ERC20']['abi']
                        )
                        token1 = trader.w3.eth.contract(
                            address=contract_info['tokens']['token1'],
                            abi=trader.abis['ERC20']['abi']
                        )

                        logger.info(f"Token0: {contract_info['tokens']['token0']}")
                        logger.info(f"Token1: {contract_info['tokens']['token1']}")
                    except Exception as token_error:
                        logger.warning(f"Could not retrieve token details: {token_error}")

                    # Additional pool information
                    logger.info(f"Pool Fee Tier: 0.3%")  # Hardcoded based on pool name

                except Exception as pool_error:
                    logger.error(f"Error retrieving pool details: {pool_error}")

            except Exception as contract_error:
                logger.error(f"Error creating contract instance: {contract_error}")

    except Exception as e:
        logger.error(f"Unhandled exception in main: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())