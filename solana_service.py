import os
import logging
import requests
import json
from datetime import datetime
from typing import Dict, List, Optional
from uagents import Model, Field
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Solana RPC endpoints
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
# For additional token data
SOLSCAN_API_URL = "https://public-api.solscan.io/token/meta"


@dataclass
class TokenRiskFactors:
    liquidity_score: float  # 0-1 score based on liquidity depth
    holder_distribution_score: float  # 0-1 score based on holder concentration
    age_score: float  # 0-1 score based on token age
    volume_score: float  # 0-1 score based on trading volume patterns
    contract_score: float  # 0-1 score based on contract verification
    # Overall risk score (0-1, higher means more risky)
    total_risk_score: float
    warnings: List[str]  # List of specific warnings/concerns
    details: Dict  # Detailed analysis data


class TokenAnalysisRequest(Model):
    token_address: str = Field(
        description="Solana token address to analyze for rugpull risk",
    )


class TokenAnalysisResponse(Model):
    risk_score: float = Field(
        description="Overall risk score (0-1, higher means more risky)",
    )
    risk_level: str = Field(
        description="Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)",
    )
    analysis_details: Dict = Field(
        description="Detailed analysis of the token including all risk factors",
    )
    warnings: List[str] = Field(
        description="List of specific warnings and concerns",
    )


async def get_token_metadata(token_address: str) -> Dict:
    """Get token metadata from Solana RPC"""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [token_address, {"encoding": "jsonParsed"}]
    }
    response = requests.post(SOLANA_RPC_URL, json=payload)
    return response.json()


async def get_token_holders(token_address: str) -> Dict:
    """Get token holder distribution data"""
    # This would typically use a service like Solscan or similar
    # For now, we'll use a placeholder implementation
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenLargestAccounts",
        "params": [token_address]
    }
    response = requests.post(SOLANA_RPC_URL, json=payload)
    return response.json()


async def get_token_liquidity(token_address: str) -> Dict:
    """Get token liquidity information from DEXes"""
    try:
        # This would typically use Jupiter or Raydium API
        # For now, we'll use a placeholder implementation
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenSupply",
            "params": [token_address]
        }
        response = requests.post(SOLANA_RPC_URL, json=payload)
        return response.json()
    except Exception as e:
        logger.error(f"Error fetching liquidity data: {str(e)}")
        return {"error": str(e)}


async def get_token_trading_history(token_address: str) -> Dict:
    """Get token trading history and volume data"""
    try:
        # This would typically use Birdeye or similar API
        # For now, we'll use a placeholder implementation
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [token_address, {"limit": 100}]
        }
        response = requests.post(SOLANA_RPC_URL, json=payload)
        return response.json()
    except Exception as e:
        logger.error(f"Error fetching trading history: {str(e)}")
        return {"error": str(e)}


async def analyze_token_risk(token_address: str) -> TokenAnalysisResponse:
    """
    Analyze a token for potential rugpull/scam characteristics

    Args:
        token_address: Solana token address to analyze

    Returns:
        TokenAnalysisResponse with detailed risk assessment
    """
    try:
        logger.info(f"Starting risk analysis for token: {token_address}")

        # Initialize risk factors
        risk_factors = TokenRiskFactors(
            liquidity_score=0.0,
            holder_distribution_score=0.0,
            age_score=0.0,
            volume_score=0.0,
            contract_score=0.0,
            total_risk_score=0.0,
            warnings=[],
            details={}
        )

        # Validate token address format
        # Solana addresses are 44 characters
        if not token_address or len(token_address) != 44:
            return TokenAnalysisResponse(
                risk_score=1.0,
                risk_level="CRITICAL",
                analysis_details={
                    "error": "Invalid token address format",
                    "address": token_address
                },
                warnings=["Invalid token address format",
                          "Address length should be 44 characters"]
            )

        # 1. Get token metadata
        metadata = await get_token_metadata(token_address)
        if "error" in metadata:
            return TokenAnalysisResponse(
                risk_score=1.0,
                risk_level="CRITICAL",
                analysis_details={
                    "error": metadata["error"]["message"],
                    "address": token_address
                },
                warnings=[
                    f"Failed to fetch token metadata: {metadata['error']['message']}",
                    "Token may not exist or be invalid"
                ]
            )
        else:
            # Analyze token age
            if "result" in metadata and "value" in metadata["result"]:
                creation_time = metadata["result"]["value"].get("data", {}).get(
                    "parsed", {}).get("info", {}).get("mintAuthority")
                if creation_time:
                    token_age = (datetime.now() -
                                 datetime.fromtimestamp(creation_time)).days
                    if token_age < 7:
                        risk_factors.age_score = 1.0
                        risk_factors.warnings.append(
                            "Token is less than 7 days old")
                    elif token_age < 30:
                        risk_factors.age_score = 0.7
                        risk_factors.warnings.append(
                            "Token is less than 30 days old")
                    risk_factors.details["token_age_days"] = token_age

        # 2. Analyze liquidity
        liquidity_data = await get_token_liquidity(token_address)
        if "result" in liquidity_data:
            supply = float(liquidity_data["result"]["value"]["amount"])
            if supply > 0:
                # Check if supply is reasonable (not too large or too small)
                if supply > 1_000_000_000_000:  # More than 1 trillion tokens
                    risk_factors.liquidity_score = 0.8
                    risk_factors.warnings.append(
                        "Suspiciously large token supply")
                elif supply < 1000:  # Less than 1000 tokens
                    risk_factors.liquidity_score = 0.6
                    risk_factors.warnings.append("Very small token supply")

                risk_factors.details["token_supply"] = supply

        # 3. Analyze trading history
        trading_data = await get_token_trading_history(token_address)
        if "result" in trading_data:
            transactions = trading_data["result"]
            if len(transactions) < 10:
                risk_factors.volume_score = 0.9
                risk_factors.warnings.append("Very low trading activity")
            elif len(transactions) < 50:
                risk_factors.volume_score = 0.6
                risk_factors.warnings.append("Low trading activity")

            # Analyze transaction patterns
            if len(transactions) > 0:
                risk_factors.details["total_transactions"] = len(transactions)
                risk_factors.details["first_transaction"] = transactions[-1]["blockTime"]
                risk_factors.details["latest_transaction"] = transactions[0]["blockTime"]

        # 4. Analyze holder distribution
        holders = await get_token_holders(token_address)
        if "result" in holders:
            holder_data = holders["result"]["value"]
            total_holders = len(holder_data)
            top_holder_percentage = float(
                holder_data[0]["amount"]) / sum(float(h["amount"]) for h in holder_data)

            # Calculate holder distribution score
            if top_holder_percentage > 0.5:
                risk_factors.holder_distribution_score = 1.0
                risk_factors.warnings.append(
                    "Extremely concentrated token ownership")
            elif top_holder_percentage > 0.3:
                risk_factors.holder_distribution_score = 0.7
                risk_factors.warnings.append(
                    "Highly concentrated token ownership")

            risk_factors.details["holder_distribution"] = {
                "total_holders": total_holders,
                "top_holder_percentage": top_holder_percentage,
                "holder_concentration_risk": risk_factors.holder_distribution_score
            }

            # Additional holder analysis
            if total_holders < 100:
                risk_factors.warnings.append("Very few token holders")
                risk_factors.holder_distribution_score = max(
                    risk_factors.holder_distribution_score, 0.8)

        # 5. Calculate overall risk score
        weights = {
            "liquidity": 0.3,
            "holder_distribution": 0.25,
            "age": 0.15,
            "volume": 0.15,
            "contract": 0.15
        }

        risk_factors.total_risk_score = (
            risk_factors.liquidity_score * weights["liquidity"] +
            risk_factors.holder_distribution_score * weights["holder_distribution"] +
            risk_factors.age_score * weights["age"] +
            risk_factors.volume_score * weights["volume"] +
            risk_factors.contract_score * weights["contract"]
        )

        # Add risk score interpretation
        risk_factors.details["risk_factors"] = {
            "liquidity_risk": risk_factors.liquidity_score,
            "holder_distribution_risk": risk_factors.holder_distribution_score,
            "age_risk": risk_factors.age_score,
            "volume_risk": risk_factors.volume_score,
            "contract_risk": risk_factors.contract_score
        }

        # Determine risk level
        if risk_factors.total_risk_score >= 0.8:
            risk_level = "CRITICAL"
        elif risk_factors.total_risk_score >= 0.6:
            risk_level = "HIGH"
        elif risk_factors.total_risk_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return TokenAnalysisResponse(
            risk_score=risk_factors.total_risk_score,
            risk_level=risk_level,
            analysis_details=risk_factors.details,
            warnings=risk_factors.warnings
        )

    except Exception as e:
        error_msg = f"Error during token analysis: {str(e)}"
        logger.error(error_msg)
        return TokenAnalysisResponse(
            risk_score=1.0,
            risk_level="CRITICAL",
            analysis_details={
                "error": error_msg,
                "address": token_address
            },
            warnings=[error_msg, "Token analysis failed"]
        )
